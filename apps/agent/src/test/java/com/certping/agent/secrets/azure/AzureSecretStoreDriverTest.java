// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.azure;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpResponse;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProperties.AzureAuthMode;
import com.certping.agent.secrets.SecretStoreProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AzureSecretStoreDriverTest {

    private static final String OWN_VAULT = "https://kv-agent.vault.azure.net";
    private static final String OWN_HANDLE = OWN_VAULT + "/secrets/cert-1";
    private static final String FOREIGN_HANDLE = "https://other.vault.azure.net/secrets/x";

    private SecretStoreProperties props;

    @BeforeEach
    void setUp() {
        props = new SecretStoreProperties();
        props.setProvider(SecretStoreProvider.AZURE_KV);
        props.getAzureKv().setVaultUri(OWN_VAULT);
        props.getAzureKv().setAuthMode(AzureAuthMode.EMULATOR);
    }

    private AzureSecretStoreDriver newDriver() {
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "local");
        d.init();
        return d;
    }

    @Test
    void provider_returnsAzureKv() {
        assertThat(newDriver().provider()).isEqualTo(SecretStoreProvider.AZURE_KV);
    }

    @Test
    void parsesHandle_acceptsCanonicalUri() {
        AzureSecretStoreDriver d = newDriver();
        assertThat(d.parsesHandle("https://kv.vault.azure.net/secrets/name")).isTrue();
        assertThat(d.parsesHandle("https://kv.vault.azure.net/secrets/name/v1abc")).isTrue();
        assertThat(d.parsesHandle("https://kv.managedhsm.azure.net/secrets/name")).isTrue();
    }

    @Test
    void parsesHandle_rejectsMalformed() {
        AzureSecretStoreDriver d = newDriver();
        assertThat(d.parsesHandle(null)).isFalse();
        assertThat(d.parsesHandle("")).isFalse();
        assertThat(d.parsesHandle("not-a-uri")).isFalse();
        assertThat(d.parsesHandle("https://kv.example.com/secrets/x")).isFalse();
        assertThat(d.parsesHandle("https://kv.vault.azure.net/certificates/x")).isFalse();
    }

    @Test
    void assertValidName_acceptsCommonSubset() {
        AzureSecretStoreDriver d = newDriver();
        assertThatCode(() -> d.assertValidName("cert-2001")).doesNotThrowAnyException();
        assertThatCode(() -> d.assertValidName("cert_2001")).doesNotThrowAnyException();
        assertThatCode(() -> d.assertValidName("AbC-1_2")).doesNotThrowAnyException();
    }

    @Test
    void assertValidName_rejectsInvalid() {
        AzureSecretStoreDriver d = newDriver();
        assertThatThrownBy(() -> d.assertValidName(null)).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> d.assertValidName("")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> d.assertValidName("has space")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> d.assertValidName("has/slash")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> d.assertValidName("has.dot")).isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void isOwnedByThisAgent_trueForOwnVaultHost() {
        AzureSecretStoreDriver d = newDriver();
        assertThat(d.isOwnedByThisAgent(OWN_HANDLE)).isTrue();
        assertThat(d.isOwnedByThisAgent(OWN_VAULT + "/secrets/cert-1/version123")).isTrue();
    }

    @Test
    void isOwnedByThisAgent_falseForForeignHostOrUnparseable() {
        AzureSecretStoreDriver d = newDriver();
        assertThat(d.isOwnedByThisAgent(FOREIGN_HANDLE)).isFalse();
        assertThat(d.isOwnedByThisAgent("not-a-uri")).isFalse();
        assertThat(d.isOwnedByThisAgent(null)).isFalse();
    }

    @Test
    void handleFor_producesCanonicalOwnStoreUri() {
        AzureSecretStoreDriver d = newDriver();
        assertThat(d.handleFor("cert-1")).isEqualTo(OWN_VAULT + "/secrets/cert-1");
    }

    @Test
    void handleFor_stripsTrailingSlashOnVaultUri() {
        props.getAzureKv().setVaultUri(OWN_VAULT + "/");
        AzureSecretStoreDriver d = newDriver();
        assertThat(d.handleFor("cert-1")).isEqualTo(OWN_VAULT + "/secrets/cert-1");
    }

    @Test
    void read_blank_throwsPermanent() {
        AzureSecretStoreDriver d = newDriver();
        assertThatThrownBy(() -> d.read(null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode()).isEqualTo("KV_URI_BLANK"));
        assertThatThrownBy(() -> d.read(""))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void read_uriMissingSecretsPath_throwsPermanent() {
        AzureSecretStoreDriver d = newDriver();
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> when(mock.buildClient()).thenReturn(mock(SecretClient.class)))) {
            assertThatThrownBy(() -> d.read("https://kv.vault.azure.net/certificates/x"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("KV_URI_INVALID"));
        }
    }

    @Test
    void read_success_returnsValue() {
        AzureSecretStoreDriver d = newDriver();
        KeyVaultSecret secret = mock(KeyVaultSecret.class);
        when(secret.getValue()).thenReturn("payload");
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.getSecret("cf-token")).thenReturn(secret);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThat(d.read("https://kv-client.vault.azure.net/secrets/cf-token"))
                    .isEqualTo("payload");
        }
    }

    @Test
    void read_stripsVersionSuffix() {
        AzureSecretStoreDriver d = newDriver();
        KeyVaultSecret secret = mock(KeyVaultSecret.class);
        when(secret.getValue()).thenReturn("payload");
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.getSecret("cf-token")).thenReturn(secret);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThat(d.read("https://kv-client.vault.azure.net/secrets/cf-token/v1abc"))
                    .isEqualTo("payload");
        }
    }

    @Test
    void read_resourceNotFound_mapsToPermanent() {
        AzureSecretStoreDriver d = newDriver();
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(404);
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.getSecret(any(String.class)))
                            .thenThrow(new ResourceNotFoundException("nope", resp));
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() ->
                    d.read("https://kv-client.vault.azure.net/secrets/missing"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("KV_SECRET_NOT_FOUND"));
        }
    }

    @Test
    void read_azure429_mapsToRetryableWithRetryAfter() {
        AzureSecretStoreDriver d = newDriver();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", "30");
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(429);
        when(resp.getHeaders()).thenReturn(headers);
        HttpResponseException throttle = new HttpResponseException("throttled", resp);

        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.getSecret(any(String.class))).thenThrow(throttle);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() ->
                    d.read("https://kv-client.vault.azure.net/secrets/cf-token"))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(ex -> {
                        assertThat(((RetryableAgentException) ex).getErrorCode())
                                .isEqualTo("KV_PROVIDER_THROTTLED");
                        assertThat(((RetryableAgentException) ex).getRetryAfter())
                                .isEqualTo(Duration.ofSeconds(30));
                    });
        }
    }

    @Test
    void read_403_mapsToPermanentAccessDenied() {
        AzureSecretStoreDriver d = newDriver();
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(403);
        when(resp.getHeaders()).thenReturn(new HttpHeaders());
        HttpResponseException denied = new HttpResponseException("denied", resp);

        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.getSecret(any(String.class))).thenThrow(denied);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() ->
                    d.read("https://kv-client.vault.azure.net/secrets/cf-token"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("KV_ACCESS_DENIED"));
        }
    }

    @Test
    void read_networkFailure_mapsToTransient() {
        AzureSecretStoreDriver d = newDriver();
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.getSecret(any(String.class)))
                            .thenThrow(new RuntimeException("connection reset"));
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() ->
                    d.read("https://kv-client.vault.azure.net/secrets/cf-token"))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    @Test
    void create_success_returnsHandleFromSdk() {
        AzureSecretStoreDriver d = newDriver();
        KeyVaultSecret stored = mock(KeyVaultSecret.class);
        when(stored.getId()).thenReturn(OWN_HANDLE + "/v1abc");
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(KeyVaultSecret.class))).thenReturn(stored);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThat(d.create("cert-1", "payload")).isEqualTo(OWN_HANDLE + "/v1abc");
        }
    }

    @Test
    void create_sdkReturnsNull_fallsBackToBaseHandle() {
        AzureSecretStoreDriver d = newDriver();
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(KeyVaultSecret.class))).thenReturn(null);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThat(d.create("cert-1", "payload")).isEqualTo(OWN_HANDLE);
        }
    }

    @Test
    void create_invalidName_throwsPermanentBeforeSdkCall() {
        AzureSecretStoreDriver d = newDriver();
        assertThatThrownBy(() -> d.create("bad name with spaces", "v"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("SECRET_STORE_NAME_INVALID"));
    }

    @Test
    void create_transientSdkFailure_mapsToTransient() {
        AzureSecretStoreDriver d = newDriver();
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(KeyVaultSecret.class)))
                            .thenThrow(new RuntimeException("KV unavailable"));
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> d.create("cert-1", "payload"))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("KV_WRITE_FAILED"));
        }
    }

    @Test
    void update_returnsHandleFromSdk() {
        AzureSecretStoreDriver d = newDriver();
        KeyVaultSecret stored = mock(KeyVaultSecret.class);
        when(stored.getId()).thenReturn(OWN_HANDLE + "/newver");
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(eq("cert-1"), eq("v2"))).thenReturn(stored);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThat(d.update(OWN_HANDLE, "v2")).isEqualTo(OWN_HANDLE + "/newver");
        }
    }

    @Test
    void delete_forOwnHandle_alsoPurgesTombstone() {
        AzureSecretStoreDriver d = newDriver();
        @SuppressWarnings("unchecked")
        com.azure.core.util.polling.SyncPoller<com.azure.security.keyvault.secrets.models.DeletedSecret, Void> poller =
                mock(com.azure.core.util.polling.SyncPoller.class);
        when(poller.waitForCompletion()).thenReturn(null);
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.beginDeleteSecret("cert-1")).thenReturn(poller);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            d.delete(OWN_HANDLE);
        }
    }

    @Test
    void delete_notFound_idempotent() {
        AzureSecretStoreDriver d = newDriver();
        HttpResponse resp = mock(HttpResponse.class);
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.beginDeleteSecret(any(String.class)))
                            .thenThrow(new ResourceNotFoundException("gone", resp));
                    when(mock.buildClient()).thenReturn(client);
                })) {
            d.delete(OWN_HANDLE);
        }
    }

    @Test
    void init_missingVaultUri_throwsIllegalState() {
        props.getAzureKv().setVaultUri("");
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "local");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("vault-uri");
    }

    @Test
    void init_emulatorOutsideLocalProfile_throwsIllegalState() {
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("EMULATOR");
    }

    @Test
    void init_nullVaultUri_throwsIllegalState() {
        props.getAzureKv().setVaultUri(null);
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "local");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("vault-uri");
    }

    @Test
    void constructor_nullProfileTolerated() {
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, null);
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void init_clientSecretMode_requiresTenantId() {
        props.getAzureKv().setAuthMode(AzureAuthMode.CLIENT_SECRET);
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("tenant-id");
    }

    @Test
    void init_clientSecretMode_requiresClientId() {
        props.getAzureKv().setAuthMode(AzureAuthMode.CLIENT_SECRET);
        props.getAzureKv().setTenantId("t");
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client-id");
    }

    @Test
    void init_clientSecretMode_requiresClientSecret() {
        props.getAzureKv().setAuthMode(AzureAuthMode.CLIENT_SECRET);
        props.getAzureKv().setTenantId("t");
        props.getAzureKv().setClientId("c");
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client-secret");
    }

    @Test
    void init_clientSecretMode_success() {
        props.getAzureKv().setAuthMode(AzureAuthMode.CLIENT_SECRET);
        props.getAzureKv().setTenantId("t");
        props.getAzureKv().setClientId("c");
        props.getAzureKv().setClientSecret("s");
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatCode(d::init).doesNotThrowAnyException();
    }

    @Test
    void init_clientCertificateMode_requiresTenantId() {
        props.getAzureKv().setAuthMode(AzureAuthMode.CLIENT_CERTIFICATE);
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void init_clientCertificateMode_requiresPath() {
        props.getAzureKv().setAuthMode(AzureAuthMode.CLIENT_CERTIFICATE);
        props.getAzureKv().setTenantId("t");
        props.getAzureKv().setClientId("c");
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client-certificate-path");
    }

    @Test
    void init_workloadIdentityMode_buildsCredential() {
        props.getAzureKv().setAuthMode(AzureAuthMode.WORKLOAD_IDENTITY);
        props.getAzureKv().setTenantId("t");
        props.getAzureKv().setClientId("c");
        props.getAzureKv().setFederatedTokenFile("/var/run/secrets/token");
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatCode(d::init).doesNotThrowAnyException();
    }

    @Test
    void init_defaultMode_buildsCredential() {
        props.getAzureKv().setAuthMode(AzureAuthMode.DEFAULT);
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatCode(d::init).doesNotThrowAnyException();
    }

    @Test
    void init_disableChallengeVerificationExplicit() {
        props.getAzureKv().setAuthMode(AzureAuthMode.DEFAULT);
        props.getAzureKv().setDisableChallengeResourceVerification(true);
        AzureSecretStoreDriver d = new AzureSecretStoreDriver(props, "prod");
        assertThatCode(d::init).doesNotThrowAnyException();
    }

    @Test
    void update_azure429_mapsToRetryable() {
        AzureSecretStoreDriver d = newDriver();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", "60");
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(429);
        when(resp.getHeaders()).thenReturn(headers);
        HttpResponseException throttle = new HttpResponseException("throttled", resp);

        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(String.class), any(String.class))).thenThrow(throttle);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> d.update(OWN_HANDLE, "v"))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void update_403_mapsToPermanentAccessDenied() {
        AzureSecretStoreDriver d = newDriver();
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(403);
        when(resp.getHeaders()).thenReturn(new HttpHeaders());
        HttpResponseException denied = new HttpResponseException("denied", resp);

        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(String.class), any(String.class))).thenThrow(denied);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> d.update(OWN_HANDLE, "v"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("KV_ACCESS_DENIED"));
        }
    }

    @Test
    void update_networkFailure_mapsToTransient() {
        AzureSecretStoreDriver d = newDriver();
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(String.class), any(String.class)))
                            .thenThrow(new RuntimeException("net down"));
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> d.update(OWN_HANDLE, "v"))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    @Test
    void update_sdkReturnsNullId_returnsInputHandle() {
        AzureSecretStoreDriver d = newDriver();
        KeyVaultSecret stored = mock(KeyVaultSecret.class);
        when(stored.getId()).thenReturn(null);
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(String.class), any(String.class))).thenReturn(stored);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThat(d.update(OWN_HANDLE, "v")).isEqualTo(OWN_HANDLE);
        }
    }

    @Test
    void delete_transientError_wrapsAsTransient() {
        AzureSecretStoreDriver d = newDriver();
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.beginDeleteSecret(any(String.class)))
                            .thenThrow(new RuntimeException("bus down"));
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThatThrownBy(() -> d.delete(OWN_HANDLE))
                    .isInstanceOf(TransientAgentException.class);
        }
    }

    @Test
    void delete_foreignHandle_noPurge() {
        AzureSecretStoreDriver d = newDriver();
        @SuppressWarnings("unchecked")
        com.azure.core.util.polling.SyncPoller<com.azure.security.keyvault.secrets.models.DeletedSecret, Void> poller =
                mock(com.azure.core.util.polling.SyncPoller.class);
        when(poller.waitForCompletion()).thenReturn(null);
        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.beginDeleteSecret(any(String.class))).thenReturn(poller);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            d.delete(FOREIGN_HANDLE);
        }
    }

    @Test
    void create_softDeletedRecoverable_recoversThenRetries() {
        AzureSecretStoreDriver d = newDriver();
        KeyVaultSecret stored = mock(KeyVaultSecret.class);
        when(stored.getId()).thenReturn(OWN_HANDLE + "/newver");
        @SuppressWarnings("unchecked")
        com.azure.core.util.polling.SyncPoller<
                com.azure.security.keyvault.secrets.models.KeyVaultSecret,
                Void> recoverPoller = mock(com.azure.core.util.polling.SyncPoller.class);
        when(recoverPoller.waitForCompletion()).thenReturn(null);
        java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger();

        try (MockedConstruction<SecretClientBuilder> ignored = Mockito.mockConstruction(
                SecretClientBuilder.class,
                Mockito.withSettings().defaultAnswer(RETURNS_SELF),
                (mock, ctx) -> {
                    SecretClient client = mock(SecretClient.class);
                    when(client.setSecret(any(KeyVaultSecret.class))).thenAnswer(inv -> {
                        if (callCount.getAndIncrement() == 0) {
                            throw new com.azure.core.exception.HttpResponseException(
                                    "ObjectIsDeletedButRecoverable", mock(HttpResponse.class));
                        }
                        return stored;
                    });
                    when(client.beginRecoverDeletedSecret(any(String.class))).thenReturn(recoverPoller);
                    when(mock.buildClient()).thenReturn(client);
                })) {
            assertThat(d.create("cert-1", "v")).isEqualTo(OWN_HANDLE + "/newver");
            assertThat(callCount.get()).isEqualTo(2);
        }
    }
}
