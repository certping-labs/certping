// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpResponse;
import com.azure.core.management.exception.ManagementError;
import com.azure.core.management.exception.ManagementException;
import com.azure.core.management.profile.AzureProfile;
import com.azure.resourcemanager.network.models.ApplicationGateway;
import com.azure.resourcemanager.AzureResourceManager;
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
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
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
class AzureAppGatewayDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private AzureCloudCredentialResolver azureCredentialResolver;

    private AzureAppGatewayDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
            "\"tenantId\":\"00000000-0000-0000-0000-000000000002\"," +
            "\"subscriptionId\":\"00000000-0000-0000-0000-000000000003\"," +
            "\"resourceGroup\":\"rg-prod\"," +
            "\"appGateway\":\"agw-prod\"," +
            "\"listeners\":[\"https-443\",\"https-8443\"]," +
            "\"keyVaultUri\":\"https://my-kv.vault.azure.net/\"}";

    private static final String TARGETS_JSON =
            "{\"sslCertName\":\"certping-wildcard\",\"listenerNames\":[\"https-443\"]}";

    // Real (self-signed) PEM material — the AGW adapter calls PemPfxUtils.toPkcs12Bytes early,
    // which parses these. Tests that don't reach that point still use the placeholder bundle.
    private static String REAL_PRIVATE_KEY_PEM;
    private static String REAL_CERT_PEM;

    @BeforeAll
    static void buildRealPem() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=agw-throttle-test.example.com");
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
        adapter = new AzureAppGatewayDeploymentAdapter(secretStore, azureCredentialResolver, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_readsCredentialFromKv_evenWhenJsonInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class);

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/appgw-cred");
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
                "\"appGateway\":\"agw-prod\"," +
                "\"listeners\":[\"https-443\"]," +
                "\"sslCertName\":\"cert\",\"keyVaultUri\":\"https://kv.vault.azure.net/\"}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("resourceGroup");
    }

    @Test
    void deploy_missingListenersInScope_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"tenantId\":\"t\",\"subscriptionId\":\"s\"," +
                "\"resourceGroup\":\"rg\",\"appGateway\":\"agw\"," +
                "\"sslCertName\":\"cert\",\"keyVaultUri\":\"https://kv.vault.azure.net/\"}");
        msg.setTargetsJson(TARGETS_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("listeners");
    }

    @Test
    void deploy_emptyListenerNames_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerNames\":[]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_listenerNotInScope_throwsPermanentTargetsInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerNames\":[\"unknown-listener\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"))
                .hasMessageContaining("not in the credential's scope.listeners");
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
                "\"appGateway\":\"agw\",\"listeners\":[\"l\"]," +
                "\"sslCertName\":\"c\",\"keyVaultUri\":\"https://kv.vault.azure.net/\"}");
        msg.setTargetsJson("{\"listenerNames\":[\"l\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    // ── throttle classification (Azure 429/Retry-After) ──────────────────────

    @Test
    void deploy_azure429FromAgwUpdate_throwsRetryableWithDeployProviderThrottled() {
        // KV import succeeds; the AGW management call throws a 429 ManagementException.
        // Adapter's ManagementException catch routes via RateLimitClassifier.fromAzure with
        // "DEPLOY_PROVIDER_THROTTLED" and surfaces the Retry-After hint.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", "30");
        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(429);
        when(mockResp.getHeaders()).thenReturn(headers);
        ManagementException throttle = new ManagementException("throttled", mockResp);

        // 1) KV import succeeds (returns a non-blank secretId).
        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {

            AzureResourceManager.Authenticated authenticated =
                    mock(AzureResourceManager.Authenticated.class, RETURNS_DEEP_STUBS);
            // nullable() (not any()) so the test tolerates the unstubbed credential resolver returning null.
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(authenticated);
            when(authenticated.withSubscription(anyString()).applicationGateways()
                    .getByResourceGroup(anyString(), anyString())).thenThrow(throttle);

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

    // ── HTTP status-code classification ────────────────────────────────────

    private void runDeployWithManagementException(int status,
                                                  Class<? extends RuntimeException> expectedType,
                                                  String expectedCode) {
        runDeployWithManagementException(status, null, expectedType, expectedCode);
    }

    private void runDeployWithManagementException(int status,
                                                  ManagementError error,
                                                  Class<? extends RuntimeException> expectedType,
                                                  String expectedCode) {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(status);
        when(mockResp.getHeaders()).thenReturn(new HttpHeaders());
        ManagementException me = new ManagementException("azure-" + status, mockResp, error);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {

            AzureResourceManager.Authenticated authenticated =
                    mock(AzureResourceManager.Authenticated.class, RETURNS_DEEP_STUBS);
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(authenticated);
            when(authenticated.withSubscription(anyString()).applicationGateways()
                    .getByResourceGroup(anyString(), anyString())).thenThrow(me);

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
        runDeployWithManagementException(400, PermanentAgentException.class, "DEPLOY_CERT_REJECTED");
    }

    @Test
    void deploy_azure401_throwsPermanentAccessDenied() {
        runDeployWithManagementException(401, PermanentAgentException.class, "DEPLOY_ACCESS_DENIED");
    }

    @Test
    void deploy_azure403_throwsPermanentPermissionDenied() {
        runDeployWithManagementException(403, PermanentAgentException.class, "DEPLOY_AZURE_PERMISSION_DENIED");
    }

    @Test
    void deploy_azure409WithInsufficientPermissionCode_throwsPermanentPermissionDenied() {
        ManagementError error = new ManagementError("ApplicationGatewayInsufficientPermissionOnSubnet",
                "does not have permission to perform action Microsoft.Network/virtualNetworks/subnets/join/action");
        runDeployWithManagementException(409, error, PermanentAgentException.class, "DEPLOY_AZURE_PERMISSION_DENIED");
    }

    @Test
    void deploy_azure409WithConflictCode_staysConflict() {
        ManagementError error = new ManagementError("Conflict", "Another operation is in progress");
        runDeployWithManagementException(409, error, PermanentAgentException.class, "DEPLOY_AZURE_CONFLICT");
    }

    @Test
    void deploy_azure404_throwsPermanentResourceNotFound() {
        runDeployWithManagementException(404, PermanentAgentException.class, "DEPLOY_RESOURCE_NOT_FOUND");
    }

    @Test
    void deploy_azure409_throwsPermanentConflict() {
        runDeployWithManagementException(409, PermanentAgentException.class, "DEPLOY_AZURE_CONFLICT");
    }

    @Test
    void deploy_azure412_throwsPermanentConflict() {
        runDeployWithManagementException(412, PermanentAgentException.class, "DEPLOY_AZURE_CONFLICT");
    }

    @Test
    void deploy_azure500_throwsTransient() {
        runDeployWithManagementException(500, TransientAgentException.class, "DEPLOY_AZURE_HTTP_ERROR");
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
        when(imported.getSecretId()).thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {

            AzureResourceManager.Authenticated authenticated =
                    mock(AzureResourceManager.Authenticated.class, RETURNS_DEEP_STUBS);
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(authenticated);
            when(authenticated.withSubscription(anyString()).applicationGateways()
                    .getByResourceGroup(anyString(), anyString())).thenThrow(hre);

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

    @Test
    void deploy_agwNotFound_throwsPermanentResourceNotFound() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {

            AzureResourceManager.Authenticated authenticated =
                    mock(AzureResourceManager.Authenticated.class, RETURNS_DEEP_STUBS);
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(authenticated);
            when(authenticated.withSubscription(anyString()).applicationGateways()
                    .getByResourceGroup(anyString(), anyString())).thenReturn(null);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_RESOURCE_NOT_FOUND"));
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
                })) {
            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_RESULT_NULL_RESOURCE_ID"));
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
                            .thenThrow(new RuntimeException("boom"));
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_AZURE_KV_IMPORT_FAILED"));
        }
    }

    @Test
    void deploy_blankDomain_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);
        msg.setDomain("");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_DOMAIN_REQUIRED"));
    }

    @Test
    void deploy_missingSslCertNameAndNoPriorResult_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerNames\":[\"https-443\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_priorResultCertName_locks() {
        // sslCertName missing from targets but prior result has it; we should reach KV stage.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerNames\":[\"https-443\"]}");
        msg.setConfigJson("{\"certificateName\":\"locked-name\"}");

        try {
            adapter.deploy(realBundle(), msg);
        } catch (PermanentAgentException e) {
            assertThat(e.getErrorCode()).isNotEqualTo("DEPLOY_TARGETS_INVALID");
        } catch (Exception ignored) {
        }
    }

    @Test
    void deploy_missingSubscriptionId_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"resourceGroup\":\"rg\",\"appGateway\":\"agw\"," +
                "\"listeners\":[\"l\"],\"keyVaultUri\":\"https://kv.vault.azure.net/\"}");
        msg.setTargetsJson("{\"sslCertName\":\"c\",\"listenerNames\":[\"l\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("subscriptionId");
    }

    @Test
    void deploy_missingAppGateway_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"subscriptionId\":\"s\",\"resourceGroup\":\"rg\"," +
                "\"listeners\":[\"l\"],\"keyVaultUri\":\"https://kv.vault.azure.net/\"}");
        msg.setTargetsJson("{\"sslCertName\":\"c\",\"listenerNames\":[\"l\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("appGateway");
    }

    @Test
    void deploy_missingKeyVaultUri_throwsPermanent() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(
                "{\"authMode\":\"SERVICE_PRINCIPAL\"," +
                "\"subscriptionId\":\"s\",\"resourceGroup\":\"rg\"," +
                "\"appGateway\":\"agw\",\"listeners\":[\"l\"]}");
        msg.setTargetsJson("{\"sslCertName\":\"c\",\"listenerNames\":[\"l\"]}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("keyVaultUri");
    }

    @Test
    void deploy_success_returnsResultWithCertNameAndSecretId() {
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
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {

            AzureResourceManager.Authenticated authenticated =
                    mock(AzureResourceManager.Authenticated.class, RETURNS_DEEP_STUBS);
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(authenticated);

            ApplicationGateway agw = mock(ApplicationGateway.class, RETURNS_DEEP_STUBS);
            when(agw.id()).thenReturn(
                    "/subscriptions/sub/resourceGroups/rg-prod/providers/Microsoft.Network/applicationGateways/agw-prod");
            when(authenticated.withSubscription(anyString()).applicationGateways()
                    .getByResourceGroup(anyString(), anyString())).thenReturn(agw);
            // update().defineSslCertificate(...) chain
            ApplicationGateway.Update update = mock(ApplicationGateway.Update.class, RETURNS_DEEP_STUBS);
            when(agw.update()).thenReturn(update);
            when(update.defineSslCertificate(anyString()).withKeyVaultSecretId(anyString()).attach())
                    .thenReturn(update);
            when(update.updateListener(anyString()).withSslCertificate(anyString()).parent())
                    .thenReturn(update);
            when(update.apply()).thenReturn(agw);

            var result = adapter.deploy(realBundle(), msg);
            assertThat(result).isNotNull();
            assertThat(result.targetResourceId()).contains("applicationGateways/agw-prod");
            assertThat(result.configJson())
                    .contains("\"certificateName\":\"certping-wildcard\"")
                    .contains("\"keyVaultSecretId\":\"https://my-kv.vault.azure.net/secrets/certping-wildcard/v1\"");
        }
    }

    @Test
    void deploy_managementException400WithManagementErrorDetails_surfacesAzureDetail() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        HttpResponse mockResp = mock(HttpResponse.class);
        when(mockResp.getStatusCode()).thenReturn(400);
        when(mockResp.getHeaders()).thenReturn(new HttpHeaders());

        ManagementError detail = mock(ManagementError.class);
        when(detail.getCode()).thenReturn("InnerCode");
        when(detail.getMessage()).thenReturn("inner-msg");

        ManagementError root = mock(ManagementError.class);
        when(root.getCode()).thenReturn("ApplicationGatewaySslCertificateInvalidData");
        when(root.getMessage()).thenReturn("Data or Password for certificate is invalid");
        when(root.getTarget()).thenReturn("sslCertificate");
        Mockito.<List<? extends ManagementError>>when(root.getDetails()).thenReturn(List.of(detail));

        ManagementException me = mock(ManagementException.class);
        when(me.getResponse()).thenReturn(mockResp);
        when(me.getValue()).thenReturn(root);
        when(me.getMessage()).thenReturn("LRO Failed");

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {

            AzureResourceManager.Authenticated authenticated =
                    mock(AzureResourceManager.Authenticated.class, RETURNS_DEEP_STUBS);
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(authenticated);
            when(authenticated.withSubscription(anyString()).applicationGateways()
                    .getByResourceGroup(anyString(), anyString())).thenThrow(me);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_CERT_REJECTED"))
                    .hasMessageContaining("ApplicationGatewaySslCertificateInvalidData")
                    .hasMessageContaining("InnerCode");
        }
    }

    @Test
    void deploy_managementExceptionNullResponse_classifiedAsTransient() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        ManagementException me = mock(ManagementException.class);
        when(me.getResponse()).thenReturn(null);
        when(me.getValue()).thenReturn(null);
        when(me.getMessage()).thenReturn("LRO timed out");

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {

            AzureResourceManager.Authenticated authenticated =
                    mock(AzureResourceManager.Authenticated.class, RETURNS_DEEP_STUBS);
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenReturn(authenticated);
            when(authenticated.withSubscription(anyString()).applicationGateways()
                    .getByResourceGroup(anyString(), anyString())).thenThrow(me);

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    @Test
    void deploy_runtimeExceptionDuringAuth_throwsAzureFailed() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn("https://my-kv.vault.azure.net/secrets/certping-wildcard/v1");

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                });
             MockedStatic<AzureResourceManager> armStatic = Mockito.mockStatic(AzureResourceManager.class)) {
            armStatic.when(() -> AzureResourceManager.authenticate(
                    nullable(TokenCredential.class),
                    nullable(AzureProfile.class)))
                    .thenThrow(new RuntimeException("auth-boom"));

            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_AZURE_FAILED"));
        }
    }

    @Test
    void deploy_priorResultMalformedJson_treatedAsFirstDeploy() {
        // readPriorCertName warns and returns null → first-deploy "requires sslCertName" error.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerNames\":[\"https-443\"]}");
        msg.setConfigJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_priorResultBlankCertName_treatedAsFirstDeploy() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson("{\"listenerNames\":[\"https-443\"]}");
        msg.setConfigJson("{\"certificateName\":\"\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_kvImportEmptyId_throwsPermanentNullResourceId_caughtAsKvImportFailed() {
        // KV returns blank secretId → adapter throws DEPLOY_RESULT_NULL_RESOURCE_ID,
        // which the importToKeyVault catch (Exception) re-wraps as DEPLOY_AZURE_KV_IMPORT_FAILED?
        // No — PermanentAgentException catch in importToKeyVault rethrows it as-is.
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setTargetsJson(TARGETS_JSON);

        KeyVaultCertificateWithPolicy imported = mock(KeyVaultCertificateWithPolicy.class);
        when(imported.getSecretId()).thenReturn(null);

        try (MockedConstruction<CertificateClientBuilder> kvCtor = Mockito.mockConstruction(
                CertificateClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mockBuilder, ctx) -> {
                    CertificateClient client = mock(CertificateClient.class);
                    when(client.importCertificate(any(ImportCertificateOptions.class))).thenReturn(imported);
                    when(mockBuilder.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> adapter.deploy(realBundle(), msg))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_RESULT_NULL_RESOURCE_ID"));
        }
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-agw-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AZURE_APP_GW);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/appgw-cred");
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
