// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpResponse;
import com.azure.core.management.exception.ManagementError;
import com.azure.core.management.exception.ManagementException;
import com.azure.core.management.profile.AzureProfile;
import com.azure.resourcemanager.cdn.CdnManager;
import com.azure.resourcemanager.cdn.fluent.models.AfdDomainInner;
import com.azure.resourcemanager.cdn.fluent.models.SecretInner;
import com.azure.resourcemanager.cdn.models.CustomerCertificateParameters;
import com.azure.resourcemanager.cdn.models.ResourceReference;
import com.azure.resourcemanager.cdn.models.SecretParameters;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.ImportCertificateOptions;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.cloud.azure.AzureCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.azure.core.exception.HttpResponseException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AzureAfdDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AzureCloudCredentialResolver azureCredentialResolver;

    private AzureAfdDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
            "\"tenantId\":\"00000000-0000-0000-0000-000000000002\"," +
            "\"subscriptionId\":\"00000000-0000-0000-0000-000000000003\"," +
            "\"resourceGroup\":\"rg-frontdoor\"," +
            "\"profileName\":\"afd-prod\"," +
            "\"keyVaultUri\":\"https://my-kv.vault.azure.net/\"," +
            "\"customDomains\":[\"api-example-com\",\"www-example-com\"]}";

    private static final String TARGETS_JSON =
            "{\"certificateName\":\"certping-wildcard\"," +
            "\"secretName\":\"certping-afd-secret\"," +
            "\"domainNames\":[\"api-example-com\"]}";

    // Real (self-signed) PEM material — the AFD adapter's KV import calls PemPfxUtils.toPkcs12Bytes,
    // which parses these. Tests that fail before that point still use the placeholder bundle.
    private static String REAL_PRIVATE_KEY_PEM;
    private static String REAL_CERT_PEM;

    @BeforeAll
    static void buildRealPem() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=afd-throttle-test.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, keyPair.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        String certB64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        REAL_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" + certB64 + "\n-----END CERTIFICATE-----\n";
        StringWriter keyWriter = new StringWriter();
        KeyPairUtils.writeKeyPair(keyPair, keyWriter);
        REAL_PRIVATE_KEY_PEM = keyWriter.toString();
    }

    private CertificateBundle realBundle() {
        return new CertificateBundle(REAL_PRIVATE_KEY_PEM, REAL_CERT_PEM, "", REAL_CERT_PEM);
    }

    @BeforeEach
    void setUp() {
        adapter = new AzureAfdDeploymentAdapter(secretStore, azureCredentialResolver, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_readsCredentialFromKv_evenWhenJsonInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class);

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/afd-deploy-cred");
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingResourceGroup_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"tenantId\":\"t\",\"subscriptionId\":\"s\"," +
                "\"profileName\":\"afd-prod\"," +
                "\"keyVaultUri\":\"https://kv.vault.azure.net/\"," +
                "\"customDomains\":[\"d1\"]}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("resourceGroup");
    }

    @Test
    void deploy_missingKeyVaultUri_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"subscriptionId\":\"s\",\"resourceGroup\":\"rg\"," +
                "\"profileName\":\"afd\"," +
                "\"customDomains\":[\"d1\"]}");
        msg.setTargetsJson(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[\"d1\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("keyVaultUri");
    }

    @Test
    void deploy_missingCustomDomainsInScope_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"subscriptionId\":\"s\",\"resourceGroup\":\"rg\"," +
                "\"profileName\":\"afd\"," +
                "\"keyVaultUri\":\"https://kv.vault.azure.net/\"}");
        msg.setTargetsJson(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[\"d1\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("customDomains");
    }

    @Test
    void deploy_emptyDomainNames_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_domainNotInScope_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(
                "{\"certificateName\":\"c\",\"secretName\":\"s\"," +
                "\"domainNames\":[\"unknown-domain\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("not in the credential's scope.customDomains");
    }

    @Test
    void deploy_invalidTargetsJson_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_unknownAuthMode_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"MAGIC\"," +
                "\"subscriptionId\":\"s\",\"resourceGroup\":\"rg\"," +
                "\"profileName\":\"afd\"," +
                "\"keyVaultUri\":\"https://kv.vault.azure.net/\"," +
                "\"customDomains\":[\"d1\"]}");
        msg.setTargetsJson(
                "{\"certificateName\":\"c\",\"secretName\":\"s\",\"domainNames\":[\"d1\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void helper_buildKvSecretArmId_defaultsKvRgAndSubToAfdScope() {
        AzureAfdScope scope = new AzureAfdScope(
                "SERVICE_PRINCIPAL",
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000003",
                null, null,
                "rg-frontdoor",
                "afd-prod",
                "https://my-kv.vault.azure.net/",
                null, null,
                List.of("api-example-com"));

        String armId = adapter.buildKvSecretArmId(scope, "frontdoor-api-cert");

        assertThat(armId).isEqualTo(
                "/subscriptions/00000000-0000-0000-0000-000000000003" +
                "/resourceGroups/rg-frontdoor" +
                "/providers/Microsoft.KeyVault/vaults/my-kv" +
                "/secrets/frontdoor-api-cert");
    }

    @Test
    void helper_buildKvSecretArmId_usesOverrideRgAndSubWhenProvided() {
        AzureAfdScope scope = new AzureAfdScope(
                "SERVICE_PRINCIPAL",
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000003",
                null, null,
                "rg-frontdoor",
                "afd-prod",
                "https://shared-kv.vault.azure.net",
                "rg-shared-platform",
                "00000000-0000-0000-0000-0000000000aa",
                List.of("api-example-com"));

        String armId = adapter.buildKvSecretArmId(scope, "frontdoor-api-cert");

        assertThat(armId).isEqualTo(
                "/subscriptions/00000000-0000-0000-0000-0000000000aa" +
                "/resourceGroups/rg-shared-platform" +
                "/providers/Microsoft.KeyVault/vaults/shared-kv" +
                "/secrets/frontdoor-api-cert");
    }

    @Test
    void helper_buildAfdSecretResourceId_formatsExpectedArmId() {
        AzureAfdScope scope = new AzureAfdScope(
                "SERVICE_PRINCIPAL",
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000003",
                null, null,
                "rg-frontdoor",
                "afd-prod",
                "https://my-kv.vault.azure.net/",
                null, null,
                List.of("api-example-com"));

        String armId = adapter.buildAfdSecretResourceId(scope, "certping-afd-secret");

        assertThat(armId).isEqualTo(
                "/subscriptions/00000000-0000-0000-0000-000000000003" +
                "/resourceGroups/rg-frontdoor" +
                "/providers/Microsoft.Cdn/profiles/afd-prod" +
                "/secrets/certping-afd-secret");
    }

    @Test
    void validateScope_allFieldsPresent_doesNotThrow() {
        AzureAfdScope scope = new AzureAfdScope(
                "SERVICE_PRINCIPAL", "t", "s", null, null,
                "rg", "profile",
                "https://kv.vault.azure.net/",
                null, null,
                List.of("d1"));
        adapter.validateScope(scope);
    }

    @Test
    void validateTargets_subsetOfScope_returnsNames() {
        AzureAfdScope scope = new AzureAfdScope(
                "SERVICE_PRINCIPAL", "t", "s", null, null,
                "rg", "profile",
                "https://kv.vault.azure.net/",
                null, null,
                List.of("d1", "d2", "d3"));
        AzureAfdTargets targets = new AzureAfdTargets("cert", "secret", List.of("d1", "d3"));

        List<String> result = adapter.validateTargets(targets, scope);

        assertThat(result).containsExactly("d1", "d3");
    }

    // ── throttle classification (Azure 429/Retry-After) ──────────────────────

    @Test
    void deploy_azure429FromAfdCall_throwsRetryableWithDeployProviderThrottled() {
        // KV import succeeds; the AFD `getSecrets().get(...)` call throws a 429
        // ManagementException. The adapter's ManagementException catch hands it to
        // RateLimitClassifier.fromAzure with "DEPLOY_PROVIDER_THROTTLED".
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", "30");
        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(429);
        when(mockResp.getHeaders()).thenReturn(headers);
        ManagementException throttle = new ManagementException("throttled", mockResp);

        // KV import returns a non-blank secretId.
        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            // nullable() (not any()) so the test tolerates the unstubbed credential resolver returning null.
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenThrow(throttle);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(ex -> {
                        assertThat(((RetryableAgentException) ex).getErrorCode())
                                .isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                        assertThat(((RetryableAgentException) ex).getRetryAfter())
                                .isEqualTo(Duration.ofSeconds(30));
                    });
        }
    }

    // ── HTTP status-code classification (ManagementException catch arms) ────

    private void runDeployWithManagementExceptionStatus(int status,
                                                         Class<? extends RuntimeException> expectedType,
                                                         String expectedCode) {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(status);
        when(mockResp.getHeaders()).thenReturn(new HttpHeaders());
        ManagementException me = new ManagementException("azure-" + status, mockResp);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenThrow(me);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
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
    void deploy_azure400_throwsPermanentCertRejected() {
        runDeployWithManagementExceptionStatus(400, PermanentAgentException.class, "DEPLOY_CERT_REJECTED");
    }

    @Test
    void deploy_azure401_throwsPermanentAccessDenied() {
        runDeployWithManagementExceptionStatus(401, PermanentAgentException.class, "DEPLOY_ACCESS_DENIED");
    }

    @Test
    void deploy_azure403_throwsPermanentPermissionDenied() {
        runDeployWithManagementExceptionStatus(403, PermanentAgentException.class, "DEPLOY_AZURE_PERMISSION_DENIED");
    }

    @Test
    void deploy_azure404_throwsPermanentResourceNotFound() {
        runDeployWithManagementExceptionStatus(404, PermanentAgentException.class, "DEPLOY_RESOURCE_NOT_FOUND");
    }

    @Test
    void deploy_azure409_throwsPermanentConflict() {
        runDeployWithManagementExceptionStatus(409, PermanentAgentException.class, "DEPLOY_AZURE_CONFLICT");
    }

    @Test
    void deploy_azure412_throwsPermanentConflict() {
        runDeployWithManagementExceptionStatus(412, PermanentAgentException.class, "DEPLOY_AZURE_CONFLICT");
    }

    @Test
    void deploy_azure500_throwsTransient() {
        runDeployWithManagementExceptionStatus(500, TransientAgentException.class, "DEPLOY_AZURE_HTTP_ERROR");
    }

    @Test
    void deploy_httpResponseException400_throwsPermanentCertRejected() {
        runHttpResponseExceptionTest(400, PermanentAgentException.class, "DEPLOY_CERT_REJECTED");
    }

    @Test
    void deploy_httpResponseException401_throwsPermanentAccessDenied() {
        runHttpResponseExceptionTest(401, PermanentAgentException.class, "DEPLOY_ACCESS_DENIED");
    }

    @Test
    void deploy_httpResponseException500_throwsTransient() {
        runHttpResponseExceptionTest(500, TransientAgentException.class, "DEPLOY_AZURE_HTTP_ERROR");
    }

    private void runHttpResponseExceptionTest(int status,
                                              Class<? extends RuntimeException> expectedType,
                                              String expectedCode) {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(status);
        when(mockResp.getHeaders()).thenReturn(new HttpHeaders());
        HttpResponseException hre = new HttpResponseException("http-" + status, mockResp);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenThrow(hre);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
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
    void helper_buildKvSecretArmId_keyVaultUriMissing_throwsPermanent() {
        AzureAfdScope scope = new AzureAfdScope(
                "SERVICE_PRINCIPAL", "t", "s", null, null,
                "rg", "profile", "", null, null, List.of("d1"));
        assertThatThrownBy(() -> adapter.buildKvSecretArmId(scope, "cert"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void helper_buildKvSecretArmId_keyVaultUriMalformed_throwsPermanent() {
        AzureAfdScope scope = new AzureAfdScope(
                "SERVICE_PRINCIPAL", "t", "s", null, null,
                "rg", "profile", "https://nodot", null, null, List.of("d1"));
        assertThatThrownBy(() -> adapter.buildKvSecretArmId(scope, "cert"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── deep coverage: formatAzureManagementError via ManagementException with ManagementError ──

    @Test
    void deploy_managementException400WithManagementErrorDetails_includesDetailInMessage() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(400);
        when(mockResp.getHeaders()).thenReturn(new HttpHeaders());

        ManagementError nestedErr = mock(ManagementError.class);
        when(nestedErr.getCode()).thenReturn("InnerCode");
        when(nestedErr.getMessage()).thenReturn("inner message");
        when(nestedErr.getTarget()).thenReturn("inner target");

        ManagementError rootErr = mock(ManagementError.class);
        when(rootErr.getCode()).thenReturn("OuterCode");
        when(rootErr.getMessage()).thenReturn("outer message");
        when(rootErr.getTarget()).thenReturn("outer target");
        // unchecked: ManagementError#getDetails returns List<? extends ManagementError>
        Mockito.<List<? extends ManagementError>>when(rootErr.getDetails()).thenReturn(List.of(nestedErr));

        ManagementException me = mock(ManagementException.class);
        when(me.getResponse()).thenReturn(mockResp);
        when(me.getValue()).thenReturn(rootErr);
        when(me.getMessage()).thenReturn("azure-400");

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenThrow(me);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_CERT_REJECTED"))
                    .hasMessageContaining("OuterCode")
                    .hasMessageContaining("InnerCode")
                    .hasMessageContaining("outer target");
        }
    }

    @Test
    void deploy_managementExceptionNullResponse_classifiedAsTransient() {
        // status == -1 path (no response) → falls through all status arms → TransientAgentException
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        ManagementException me = mock(ManagementException.class);
        when(me.getResponse()).thenReturn(null);
        when(me.getValue()).thenReturn(null);
        when(me.getMessage()).thenReturn("LRO failed");

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenThrow(me);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    // ── upsertAfdSecret: existing secret already references same KV → no-op (success path) ──

    @Test
    void deploy_successWithExistingMatchingSecret_noOpsAndBinds() {
        // Existing secret references same KV id with useLatestVersion=true → no recreate.
        // bindSecretToCustomDomain finds the domain by hostname; ends with a successful
        // result containing the locked certificateName and secretName.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        // Build the kvSecretArmId we expect: /subscriptions/.../secrets/certping-wildcard
        String expectedKvArmId =
                "/subscriptions/00000000-0000-0000-0000-000000000003" +
                "/resourceGroups/rg-frontdoor" +
                "/providers/Microsoft.KeyVault/vaults/my-kv" +
                "/secrets/certping-wildcard";
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        // existing AFD secret referencing the same KV id
        SecretInner existing = mock(SecretInner.class);
        CustomerCertificateParameters params = mock(CustomerCertificateParameters.class);
        ResourceReference ref = mock(ResourceReference.class);
        when(ref.id()).thenReturn(expectedKvArmId);
        when(params.secretSource()).thenReturn(ref);
        when(params.useLatestVersion()).thenReturn(true);
        when(existing.parameters()).thenReturn((SecretParameters) params);

        AfdDomainInner domainInner = mock(AfdDomainInner.class);
        when(domainInner.hostname()).thenReturn("api-example-com");
        when(domainInner.name()).thenReturn("api-example-com-resourceName");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenReturn(existing);
            // listByProfile -> iterable containing our domain
            when(cdnManager.serviceClient().getAfdCustomDomains()
                    .listByProfile(anyString(), anyString()))
                    .thenReturn(new com.azure.core.http.rest.PagedIterable<>(
                            new com.azure.core.http.rest.PagedFlux<>(() ->
                                    reactor.core.publisher.Mono.just(
                                            new com.azure.core.http.rest.PagedResponseBase<>(
                                                    null, 200, null, List.of(domainInner), null, null)))));
            // beginUpdate returns a SyncPoller mock whose getFinalResult returns null
            com.azure.core.util.polling.SyncPoller<?, ?> poller = mock(com.azure.core.util.polling.SyncPoller.class);
            Mockito.<Object>when(cdnManager.serviceClient().getAfdCustomDomains()
                    .beginUpdate(anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(poller);

            var result = adapter.deploy(realBundle(), msg);
            assertThat(result).isNotNull();
            assertThat(result.targetResourceId())
                    .contains("/providers/Microsoft.Cdn/profiles/afd-prod/secrets/certping-afd-secret");
            assertThat(result.configJson())
                    .contains("\"certificateName\":\"certping-wildcard\"")
                    .contains("\"secretName\":\"certping-afd-secret\"");
        }
    }

    @Test
    void deploy_existingSecret404_fallsThroughToCreate() {
        // get() throws 404 ManagementException → treated as not-existing → create path.
        // We then make beginUpdate throw a non-throttling 500 so the overall deploy fails
        // transient but covers the create branch.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpResponse resp404 = mock(HttpResponse.class);
        when(resp404.getStatusCode()).thenReturn(404);
        when(resp404.getHeaders()).thenReturn(new HttpHeaders());
        ManagementException notFound = new ManagementException("no secret", resp404);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        AfdDomainInner domainInner = mock(AfdDomainInner.class);
        when(domainInner.hostname()).thenReturn("api-example-com");
        when(domainInner.name()).thenReturn("api-domain");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenThrow(notFound);
            // create returns null on success
            when(cdnManager.serviceClient().getSecrets()
                    .create(anyString(), anyString(), anyString(), any(SecretInner.class), any()))
                    .thenReturn(null);

            when(cdnManager.serviceClient().getAfdCustomDomains()
                    .listByProfile(anyString(), anyString()))
                    .thenReturn(new com.azure.core.http.rest.PagedIterable<>(
                            new com.azure.core.http.rest.PagedFlux<>(() ->
                                    reactor.core.publisher.Mono.just(
                                            new com.azure.core.http.rest.PagedResponseBase<>(
                                                    null, 200, null, List.of(domainInner), null, null)))));
            com.azure.core.util.polling.SyncPoller<?, ?> poller = mock(com.azure.core.util.polling.SyncPoller.class);
            Mockito.<Object>when(cdnManager.serviceClient().getAfdCustomDomains()
                    .beginUpdate(anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(poller);

            var result = adapter.deploy(realBundle(), msg);
            assertThat(result).isNotNull();
        }
    }

    @Test
    void deploy_existingSecretDifferentKv_deletesAndRecreates() {
        // Existing references a DIFFERENT KV id → delete + create branch.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        SecretInner existing = mock(SecretInner.class);
        CustomerCertificateParameters params = mock(CustomerCertificateParameters.class);
        ResourceReference ref = mock(ResourceReference.class);
        when(ref.id()).thenReturn("/subscriptions/x/different-vault/secrets/different");
        when(params.secretSource()).thenReturn(ref);
        when(params.useLatestVersion()).thenReturn(true);
        when(existing.parameters()).thenReturn((SecretParameters) params);

        AfdDomainInner domainInner = mock(AfdDomainInner.class);
        when(domainInner.hostname()).thenReturn("api-example-com");
        when(domainInner.name()).thenReturn("api-domain");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenReturn(existing);
            when(cdnManager.serviceClient().getAfdCustomDomains()
                    .listByProfile(anyString(), anyString()))
                    .thenReturn(new com.azure.core.http.rest.PagedIterable<>(
                            new com.azure.core.http.rest.PagedFlux<>(() ->
                                    reactor.core.publisher.Mono.just(
                                            new com.azure.core.http.rest.PagedResponseBase<>(
                                                    null, 200, null, List.of(domainInner), null, null)))));
            com.azure.core.util.polling.SyncPoller<?, ?> poller = mock(com.azure.core.util.polling.SyncPoller.class);
            Mockito.<Object>when(cdnManager.serviceClient().getAfdCustomDomains()
                    .beginUpdate(anyString(), anyString(), anyString(), any(), any()))
                    .thenReturn(poller);

            var result = adapter.deploy(realBundle(), msg);
            assertThat(result).isNotNull();
            // Verify delete was called
            verify(cdnManager.serviceClient().getSecrets())
                    .delete(anyString(), anyString(), anyString());
        }
    }

    @Test
    void deploy_bindFails_domainNotFoundInProfile_throwsPermanent() {
        // listByProfile returns no matching hostname → bindSecretToCustomDomain throws
        // DEPLOY_RESOURCE_NOT_FOUND, which propagates through PermanentAgentException catch arm.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        AfdDomainInner other = mock(AfdDomainInner.class);
        when(other.hostname()).thenReturn("nope-not-the-one");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {

            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);
            // No existing AFD secret -> 404 path
            HttpResponse resp404 = mock(HttpResponse.class);
            when(resp404.getStatusCode()).thenReturn(404);
            when(resp404.getHeaders()).thenReturn(new HttpHeaders());
            when(cdnManager.serviceClient().getSecrets().get(anyString(), anyString(), anyString()))
                    .thenThrow(new ManagementException("nope", resp404));
            when(cdnManager.serviceClient().getSecrets()
                    .create(anyString(), anyString(), anyString(), any(SecretInner.class), any()))
                    .thenReturn(null);

            when(cdnManager.serviceClient().getAfdCustomDomains()
                    .listByProfile(anyString(), anyString()))
                    .thenReturn(new com.azure.core.http.rest.PagedIterable<>(
                            new com.azure.core.http.rest.PagedFlux<>(() ->
                                    reactor.core.publisher.Mono.just(
                                            new com.azure.core.http.rest.PagedResponseBase<>(
                                                    null, 200, null, List.of(other), null, null)))));

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_RESOURCE_NOT_FOUND"));
        }
    }

    @Test
    void deploy_kvImportRuntimeException_throwsPermanentKvImportFailed() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class)))
                            .thenThrow(new RuntimeException("kv boom"));
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {
            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class), nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_AZURE_KV_IMPORT_FAILED"));
        }
    }

    @Test
    void deploy_kvImportEmptySecretId_throwsPermanentNullResourceId() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn("");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {
            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class), nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_RESULT_NULL_RESOURCE_ID"));
        }
    }

    @Test
    void deploy_priorResultLocksCertNameAndSecretName_whenTargetsBlank() {
        // targets has no certificateName / secretName → prior result locks them.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"domainNames\":[\"api-example-com\"]}");
        msg.setConfigJson(
                "{\"certificateName\":\"locked-cert\",\"secretName\":\"locked-secret\"}");

        // KV import throws to fast-exit but we exercise resolveEffectiveName + readPriorResultField
        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class)))
                            .thenThrow(new RuntimeException("after-resolve"));
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {
            CdnManager cdnManager = mock(CdnManager.class, RETURNS_DEEP_STUBS);
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class), nullable(AzureProfile.class)))
                    .thenReturn(cdnManager);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_AZURE_KV_IMPORT_FAILED"));
        }
    }

    @Test
    void deploy_firstDeployNoPriorAndBlankCertName_throwsTargetsInvalid() {
        // targets.certificateName/secretName blank and no priors → throws on resolveEffectiveName
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"domainNames\":[\"api-example-com\"]}");

        assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_priorResultMalformedJson_treatedAsFirstDeploy() {
        // readPriorResultField catches exception → returns null
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"domainNames\":[\"api-example-com\"]}");
        msg.setConfigJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_blankDomainNameInTargets_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(
                "{\"certificateName\":\"c\",\"secretName\":\"s\"," +
                "\"domainNames\":[\"   \"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("non-blank");
    }

    @Test
    void deploy_runtimeExceptionAfterAuth_throwsAzureFailed() {
        // CdnManager.authenticate static throws unchecked → fallthrough to generic Exception arm.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId())
                .thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<CdnManager> cdnStatic = Mockito.mockStatic(CdnManager.class)) {
            cdnStatic.when(() -> CdnManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenThrow(new RuntimeException("oops"));

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_AZURE_FAILED"));
        }
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-afd-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AZURE_AFD);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/afd-deploy-cred");
        return msg;
    }

    private CertificateBundle buildBundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----",
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
