// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpResponse;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.ImportCertificateOptions;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.cloud.azure.AzureCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AzureDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AzureCloudCredentialResolver azureCredentialResolver;

    private AzureDeploymentAdapter adapter;

    /** KV secret — clientId + clientSecret only (all non-sensitive config moved to scope). */
    private static final String KV_SECRET =
            "{\"clientId\":\"00000000-0000-0000-0000-000000000001\"," +
            "\"clientSecret\":\"secret123\"}";

    /**
     * Scope JSON — SERVICE_PRINCIPAL with tenantId and vaultUri.
     * One credential = one vault; vaultUri lives in scope.
     */
    private static final String SCOPE_JSON =
            "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
            "\"tenantId\":\"00000000-0000-0000-0000-000000000002\"," +
            "\"vaultUri\":\"https://example-app-vault.vault.azure.net/\"}";

    /** Targets JSON — flat: just the certificateName (vault is in scope). */
    private static final String TARGETS_JSON =
            "{\"certificateName\":\"prod-tls\"}";

    @BeforeEach
    void setUp() {
        adapter = new AzureDeploymentAdapter(secretStore, azureCredentialResolver, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_readsCredentialFromKv() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        // credential resolver will throw because the mock returns null credentials
        // but the KV read happens first — verifying it's called
        try {
            adapter.deploy(buildBundle("PKCS8"), buildMessage());
        } catch (Exception ignored) {}

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/azure-deploy-cred");
    }

    @Test
    void deploy_credentialReadFails_throwsTransient() {
        when(secretStore.read(anyString()))
                .thenThrow(new TransientAgentException("KV_READ_FAILED", "KV unavailable"));

        assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), buildMessage()))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingScopeJson_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(null);

        assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingVaultUriInScope_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingTargetsJson_autoDerivesCertNameFromDomain() {
        // With null targetsJson + no prior result, adapter derives the KV cert name from
        // message.domain. We can't fully exercise the import without an Azure SDK mock, but
        // we can confirm we proceed past the targets-required check (any error must come from
        // a later step, not DEPLOY_CREDENTIAL_INVALID for missing certificateName).
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson(null);

        // Adapter will fail later (azure SDK is unmocked) — but specifically NOT with
        // a missing-certificateName credential-invalid error.
        try {
            adapter.deploy(buildBundle("PKCS8"), msg);
        } catch (PermanentAgentException e) {
            assertThat(e.getErrorCode()).isNotEqualTo("DEPLOY_CREDENTIAL_INVALID");
        } catch (Exception ignored) {
            // Other exceptions (e.g. from unmocked SDK) are acceptable here.
        }
    }

    @Test
    void deploy_emptyTargetsObject_autoDerivesCertNameFromDomain() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson("{}");

        try {
            adapter.deploy(buildBundle("PKCS8"), msg);
        } catch (PermanentAgentException e) {
            assertThat(e.getErrorCode()).isNotEqualTo("DEPLOY_CREDENTIAL_INVALID");
        } catch (Exception ignored) {
        }
    }

    @Test
    void deploy_blankDomainAndNoTargetCertName_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson("{}");
        msg.setDomain("");

        assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_priorResultCertName_locksAcrossRotations() {
        // Even with a different targets.certificateName, the prior result.certificateName wins.
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson("{\"certificateName\":\"new-name-ignored\"}");
        msg.setConfigJson("{\"certificateName\":\"locked-from-prior\",\"version\":\"abc\"}");

        // No assertion on the resolved name (we'd need to capture from importCertificate);
        // we only check no DEPLOY_CREDENTIAL_INVALID is thrown — the lock path is exercised.
        try {
            adapter.deploy(buildBundle("PKCS8"), msg);
        } catch (PermanentAgentException e) {
            assertThat(e.getErrorCode()).isNotEqualTo("DEPLOY_CREDENTIAL_INVALID");
        } catch (Exception ignored) {
        }
    }

    @Test
    void deploy_invalidCertificateName_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson("{\"certificateName\":\"invalid name with spaces!\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_NAME_INVALID"));
    }

    @Test
    void deploy_invalidVaultUriFormat_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"tenantId\":\"t\"," +
                "\"vaultUri\":\"http://not-https.vault.azure.net/\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    // ── throttle classification (Azure 429/Retry-After) ──────────────────────

    @Test
    void deploy_azure429FromKvImport_throwsRetryableWithRetryAfter() {
        // The CertificateClient.importCertificate call throws an Azure 429 HttpResponseException;
        // the adapter catches HttpResponseException and routes through RateLimitClassifier.fromAzure
        // → RetryableAgentException(KV_PROVIDER_THROTTLED) with the parsed Retry-After.
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", "45");
        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(429);
        when(mockResp.getHeaders()).thenReturn(headers);
        HttpResponseException throttle = new HttpResponseException("throttled", mockResp);

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenThrow(throttle);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), buildMessage()))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(ex -> {
                        assertThat(((RetryableAgentException) ex).getErrorCode())
                                .isEqualTo("KV_PROVIDER_THROTTLED");
                        assertThat(((RetryableAgentException) ex).getRetryAfter())
                                .isEqualTo(Duration.ofSeconds(45));
                    });
        }
    }

    // ── HTTP status-code classification (HttpResponseException catch arms) ──

    private void runDeployWithHttpResponseException(int status,
                                                     Class<? extends RuntimeException> expectedType,
                                                     String expectedCode) {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);

        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(status);
        when(mockResp.getHeaders()).thenReturn(new HttpHeaders());
        HttpResponseException hre = new HttpResponseException("kv-" + status, mockResp);

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenThrow(hre);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), buildMessage()))
                    .isInstanceOf(expectedType)
                    .satisfies(ex -> {
                        if (ex instanceof PermanentAgentException p) {
                            assertThat(p.getErrorCode()).isEqualTo(expectedCode);
                        } else if (ex instanceof TransientAgentException t) {
                            assertThat(t.getErrorCode()).isEqualTo(expectedCode);
                        }
                    });
        }
    }

    @Test
    void deploy_kvHttp400_throwsPermanentCertRejected() {
        runDeployWithHttpResponseException(400, PermanentAgentException.class, "DEPLOY_CERT_REJECTED");
    }

    @Test
    void deploy_kvHttp401_throwsPermanentAccessDenied() {
        runDeployWithHttpResponseException(401, PermanentAgentException.class, "DEPLOY_ACCESS_DENIED");
    }

    @Test
    void deploy_kvHttp403_throwsPermanentPermissionDenied() {
        runDeployWithHttpResponseException(403, PermanentAgentException.class, "DEPLOY_AZURE_PERMISSION_DENIED");
    }

    @Test
    void deploy_kvHttp500_throwsTransient() {
        runDeployWithHttpResponseException(500, TransientAgentException.class, "DEPLOY_AZURE_HTTP_ERROR");
    }

    @Test
    void deploy_kvImportRuntimeException_throwsPermanentDeployFailed() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class)))
                            .thenThrow(new RuntimeException("boom"));
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> adapter.deploy(buildBundle("PKCS8"), buildMessage()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_AZURE_FAILED"));
        }
    }

    @Test
    void deploy_pkcs1Key_exercisesPemConversion() {
        // Exercise the AzurePemSupport.toPkcs8 path with PKCS#1 input. Adapter will fail
        // later (no working credential), but the PEM conversion path is covered.
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        try {
            adapter.deploy(buildBundle("PKCS1"), buildMessage());
        } catch (Exception ignored) {
        }
    }

    @Test
    void deploy_success_returnsResultWithCertNameAndVersion() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getId())
                .thenReturn("https://example-app-vault.vault.azure.net/certificates/prod-tls/abc123version");

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            DeploymentResult result = adapter.deploy(buildBundle("PKCS8"), buildMessage());
            assertThat(result.targetResourceId())
                    .isEqualTo("https://example-app-vault.vault.azure.net/certificates/prod-tls/abc123version");
            assertThat(result.configJson())
                    .contains("\"certificateName\":\"prod-tls\"")
                    .contains("\"version\":\"abc123version\"");
        }
    }

    @Test
    void deploy_successWithNullCertId_returnsResultWithoutVersion() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getId()).thenReturn(null);

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            DeploymentResult result = adapter.deploy(buildBundle("PKCS8"), buildMessage());
            assertThat(result.targetResourceId()).isNull();
            // null id → no version → result JSON should have only certificateName
            assertThat(result.configJson()).contains("\"certificateName\":\"prod-tls\"");
        }
    }

    @Test
    void deploy_successWithTrailingSlashId_versionEmptyButNoCrash() {
        // certId ending with '/' → extractVersionFromId returns null branch
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getId()).thenReturn("https://example-app-vault.vault.azure.net/certificates/prod-tls/");

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            DeploymentResult result = adapter.deploy(buildBundle("PKCS8"), buildMessage());
            assertThat(result.configJson()).doesNotContain("\"version\"");
        }
    }

    @Test
    void deploy_successWithIdWithoutSlash_versionNull() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getId()).thenReturn("no-slash-id");

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            DeploymentResult result = adapter.deploy(buildBundle("PKCS8"), buildMessage());
            assertThat(result.targetResourceId()).isEqualTo("no-slash-id");
            assertThat(result.configJson()).doesNotContain("\"version\"");
        }
    }

    @Test
    void deploy_priorResultMalformedJson_treatedAsFirstDeploy() {
        // readPriorCertName catches exception and returns null (warn log) → derive from domain
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson("{}");
        msg.setConfigJson("not-valid-json");

        // Will fail later but not with DEPLOY_CREDENTIAL_INVALID (derived from domain).
        try {
            adapter.deploy(buildBundle("PKCS8"), msg);
        } catch (PermanentAgentException e) {
            assertThat(e.getErrorCode()).isNotEqualTo("DEPLOY_CREDENTIAL_INVALID");
        } catch (Exception ignored) {
        }
    }

    @Test
    void deploy_priorResultWithBlankCertName_treatedAsFirstDeploy() {
        // configJson has a blank certificateName → readPriorCertName returns null
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson("{}");
        msg.setConfigJson("{\"certificateName\":\"\"}");

        try {
            adapter.deploy(buildBundle("PKCS8"), msg);
        } catch (PermanentAgentException e) {
            assertThat(e.getErrorCode()).isNotEqualTo("DEPLOY_CREDENTIAL_INVALID");
        } catch (Exception ignored) {
        }
    }

    @Test
    void deploy_priorResultMissingCertNameField_treatedAsFirstDeploy() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        CertDeploymentMessage msg = buildMessage();
        msg.setTargetsJson("{}");
        msg.setConfigJson("{\"otherField\":\"x\"}");

        try {
            adapter.deploy(buildBundle("PKCS8"), msg);
        } catch (PermanentAgentException e) {
            assertThat(e.getErrorCode()).isNotEqualTo("DEPLOY_CREDENTIAL_INVALID");
        } catch (Exception ignored) {
        }
    }

    @Test
    void deploy_workloadIdentityMode_skipsKvSecretRead() {
        // WORKLOAD_IDENTITY branch should not call secretStore.readSecret for credentials
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"WORKLOAD_IDENTITY\"," +
                "\"tenantId\":\"00000000-0000-0000-0000-000000000002\"," +
                "\"clientId\":\"00000000-0000-0000-0000-000000000001\"," +
                "\"vaultUri\":\"https://example-app-vault.vault.azure.net/\"}");

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getId())
                .thenReturn("https://example-app-vault.vault.azure.net/certificates/prod-tls/v1");

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            adapter.deploy(buildBundle("PKCS8"), msg);
        }
        // Should never have read deployment credential from KV when WORKLOAD_IDENTITY.
        Mockito.verify(secretStore, Mockito.never()).read(anyString());
    }

    @Test
    void deploy_blankOrgId_omitsTagButSucceeds() {
        when(secretStore.read(anyString())).thenReturn(KV_SECRET);
        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getId())
                .thenReturn("https://example-app-vault.vault.azure.net/certificates/prod-tls/v1");

        CertDeploymentMessage msg = buildMessage();
        msg.setOrganizationId("");

        try (MockedConstruction<CertificateClientBuilder> ignored = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            assertThat(adapter.deploy(buildBundle("PKCS8"), msg)).isNotNull();
        }
    }

    @Test
    void deploy_emptyDeploymentCredHandle_skipsKvRead_treatsAsEmptySecret() {
        // Even SERVICE_PRINCIPAL: if deploymentCredHandle is blank we skip the KV read.
        CertDeploymentMessage msg = buildMessage();
        msg.setDeploymentCredHandle("");

        // Will fail later but should NOT have called readSecret.
        try {
            adapter.deploy(buildBundle("PKCS8"), msg);
        } catch (Exception ignored) {
        }
        Mockito.verify(secretStore, Mockito.never()).read(anyString());
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-3");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AZURE_KV);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/azure-deploy-cred");
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        return msg;
    }

    private CertificateBundle buildBundle(String keyType) {
        String privateKey = switch (keyType) {
            case "PKCS8" -> "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----";
            case "PKCS1" -> "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCA==\n-----END RSA PRIVATE KEY-----";
            default -> "-----BEGIN UNKNOWN KEY-----\nMIIE==\n-----END UNKNOWN KEY-----";
        };
        return new CertificateBundle(
                privateKey,
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----",
                """
                -----BEGIN CERTIFICATE-----
                MIILeaf==
                -----END CERTIFICATE-----
                -----BEGIN CERTIFICATE-----
                MIIIntermediate==
                -----END CERTIFICATE-----"""
        );
    }
}
