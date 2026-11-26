// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpResponse;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.models.CertificateKeyType;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.CertificateProperties;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.certificates.models.SubjectAlternativeNames;
import com.certping.agent.deployment.cloud.azure.AzureAuthMode;
import com.certping.agent.deployment.cloud.azure.AzureAuthScope;
import com.certping.agent.deployment.cloud.azure.AzureAuthSecret;
import com.certping.agent.deployment.cloud.azure.AzureCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AzureKvDiscoveryAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private CertificateClient             certificateClient;
    @Mock private AzureCloudCredentialResolver  azureCredentialResolver;

    private AzureKvDiscoveryAdapter adapter;

    private static final String VALID_CRED_JSON = """
            {
              "tenantId":     "11111111-1111-1111-1111-111111111111",
              "clientId":     "22222222-2222-2222-2222-222222222222",
              "clientSecret": "test-secret",
              "vaultUri":     "https://my-kv.vault.azure.net/"
            }
            """;

    private static final String SCOPE_JSON_SP = """
            {
              "authMode": "SERVICE_PRINCIPAL",
              "tenantId": "11111111-1111-1111-1111-111111111111",
              "vaultUri": "https://scoped-kv.vault.azure.net/"
            }
            """;

    private static final String SCOPE_JSON_WI = """
            {
              "authMode": "WORKLOAD_IDENTITY",
              "tenantId": "11111111-1111-1111-1111-111111111111",
              "vaultUri": "https://wi-kv.vault.azure.net/"
            }
            """;

    private static final String THIN_SP_SECRET = """
            {"clientId":"22222222-2222-2222-2222-222222222222","clientSecret":"test-secret"}
            """;

    @BeforeEach
    void setUp() {
        adapter = new AzureKvDiscoveryAdapter(secretStore, JsonMapper.builderWithJackson2Defaults().build(), azureCredentialResolver);
    }

    // ------------------------------------------------------------------ //
    //  Legacy — full credential JSON in KV secret (no credentialScopeJson)
    // ------------------------------------------------------------------ //

    @Test
    void discover_legacy_invalidCredentialJson_throwsPermanentException() {
        when(secretStore.read(anyString())).thenReturn("not-json");

        assertThatThrownBy(() -> adapter.discover(buildLegacyMessage()))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void discover_legacy_missingVaultUri_throwsPermanentException() {
        String json = """
                {"tenantId":"11111111-1111-1111-1111-111111111111",
                 "clientId":"22222222-2222-2222-2222-222222222222",
                 "clientSecret":"s"}
                """;
        when(secretStore.read(anyString())).thenReturn(json);

        assertThatThrownBy(() -> adapter.discover(buildLegacyMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("vaultUri");
    }

    @Test
    void discover_legacy_allowedVaultsFallback_usedAsVaultUri() {
        String json = """
                {"tenantId":"11111111-1111-1111-1111-111111111111",
                 "allowedVaults":["https://wli-kv.vault.azure.net/"]}
                """;
        when(secretStore.read(anyString())).thenReturn(json);

        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(certificateClient).when(spy).buildClient(eq("https://wli-kv.vault.azure.net/"), any());
        doReturn(List.of()).when(spy).listProperties(certificateClient);

        List<DiscoveredCertEntry> result = spy.discover(buildLegacyMessage());

        assertThat(result).isEmpty();
        verify(spy).buildClient(eq("https://wli-kv.vault.azure.net/"), any());
    }

    @Test
    void discover_legacy_workloadIdentity_doesNotRequireClientIdOrSecret() {
        String json = """
                {"tenantId":"11111111-1111-1111-1111-111111111111",
                 "allowedVaults":["https://wli-kv.vault.azure.net/"]}
                """;
        when(secretStore.read(anyString())).thenReturn(json);

        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(certificateClient).when(spy).buildClient(anyString(), any());
        doReturn(List.of()).when(spy).listProperties(certificateClient);

        assertThat(spy.discover(buildLegacyMessage())).isEmpty();
    }

    @Test
    void discover_legacy_missingTenantId_throwsPermanentException() {
        String json = """
                {"clientId":"22222222-2222-2222-2222-222222222222",
                 "clientSecret":"s",
                 "vaultUri":"https://kv.vault.azure.net/"}
                """;
        when(secretStore.read(anyString())).thenReturn(json);

        assertThatThrownBy(() -> adapter.discover(buildLegacyMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("tenantId");
    }

    @Test
    void discover_legacy_readsCredentialFromCorrectKvPath() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        assertThatThrownBy(() -> adapter.discover(buildLegacyMessage()))
                .isInstanceOf(PermanentAgentException.class);

        verify(secretStore).read("https://kv-test.vault.azure.net/secrets/azure-kv-cred");
    }

    @Test
    void discover_legacy_missingKvPath_throws() {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setOrganizationId("org-1");
        msg.setTargetType(TargetType.AZURE_KV);
        msg.setDeploymentCredHandle(null);

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("deploymentCredHandle");
    }

    // ------------------------------------------------------------------ //
    //  Scope-based — matches credential_references.config + thin KV secret
    // ------------------------------------------------------------------ //

    @Test
    void discover_scope_servicePrincipal_usesVaultFromScopeAndResolver() {
        when(secretStore.read(anyString())).thenReturn(THIN_SP_SECRET);
        TokenCredential resolved = mock(TokenCredential.class);
        when(azureCredentialResolver.resolve(
                eq(AzureAuthMode.SERVICE_PRINCIPAL),
                eq(new AzureAuthScope("11111111-1111-1111-1111-111111111111", null, null, null)),
                any(AzureAuthSecret.class),
                eq("Azure KV Discovery")))
                .thenReturn(resolved);

        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(certificateClient).when(spy).buildClient(eq("https://scoped-kv.vault.azure.net/"), eq(resolved));
        doReturn(List.of()).when(spy).listProperties(certificateClient);

        List<DiscoveredCertEntry> result = spy.discover(buildScopedMessage(SCOPE_JSON_SP));

        assertThat(result).isEmpty();
        verify(secretStore).read("https://kv-test.vault.azure.net/secrets/azure-kv-cred");
        verify(spy).buildClient(eq("https://scoped-kv.vault.azure.net/"), eq(resolved));
    }

    @Test
    void discover_scope_workloadIdentity_doesNotReadDeploymentSecret() {
        CertDiscoveryMessage msg = buildScopedMessage(SCOPE_JSON_WI);

        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(certificateClient).when(spy).buildClient(eq("https://wi-kv.vault.azure.net/"), any());
        doReturn(List.of()).when(spy).listProperties(certificateClient);

        assertThat(spy.discover(msg)).isEmpty();

        verify(secretStore, never()).read(anyString());
        verify(azureCredentialResolver, never()).resolve(any(), any(), any(), anyString());
        verify(spy).buildClient(eq("https://wi-kv.vault.azure.net/"), any());
    }

    @Test
    void discover_scope_invalidJson_throws() {
        CertDiscoveryMessage msg = buildScopedMessage("{not-json");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("credentialScopeJson");
    }

    @Test
    void discover_scope_invalidVaultUriFormat_throws() {
        String badVaultScope = """
                {
                  "authMode": "WORKLOAD_IDENTITY",
                  "tenantId": "11111111-1111-1111-1111-111111111111",
                  "vaultUri": "https://example.com/not-a-vault/"
                }
                """;

        assertThatThrownBy(() -> adapter.discover(buildScopedMessage(badVaultScope)))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("vaultUri");
    }

    // ------------------------------------------------------------------ //
    //  discoverCertificates — uses spy to inject listProperties results
    // ------------------------------------------------------------------ //

    @Test
    void discoverCertificates_emptyVault_returnsEmptyList() {
        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(List.of()).when(spy).listProperties(certificateClient);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).isEmpty();
    }

    @Test
    void discoverCertificates_accessDenied_throwsPermanentException() {
        HttpResponse httpResponse = mock(HttpResponse.class);
        HttpResponseException forbidden = new HttpResponseException("Forbidden", httpResponse);

        AzureKvDiscoveryAdapter spy = spy(adapter);
        doThrow(forbidden).when(spy).listProperties(certificateClient);

        assertThatThrownBy(() -> spy.discoverCertificates(certificateClient, "org-1"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("access denied");
    }

    @Test
    void discoverCertificates_transientError_throwsTransientException() {
        AzureKvDiscoveryAdapter spy = spy(adapter);
        doThrow(new RuntimeException("network timeout")).when(spy).listProperties(certificateClient);

        assertThatThrownBy(() -> spy.discoverCertificates(certificateClient, "org-1"))
                .isInstanceOf(TransientAgentException.class)
                .hasMessageContaining("Azure KV discovery failed");
    }

    @Test
    void discoverCertificates_skipsFailedCerts_andContinues() {
        CertificateProperties goodProps = mockCertProps("good-cert");
        CertificateProperties badProps  = mockCertProps("bad-cert");

        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(List.of(goodProps, badProps)).when(spy).listProperties(certificateClient);

        KeyVaultCertificateWithPolicy goodCert = buildMockCert(
                "https://kv.vault.azure.net/certificates/good-cert/v1",
                "CN=good.example.com", List.of("good.example.com"),
                OffsetDateTime.of(2025, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC),
                OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC),
                true);

        when(certificateClient.getCertificate("good-cert")).thenReturn(goodCert);
        when(certificateClient.getCertificate("bad-cert")).thenThrow(new RuntimeException("fetch failed"));

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getDomain()).isEqualTo("good.example.com");
    }

    @Test
    void discoverWithFailedScopes_unreadableCert_reportsVaultAsFailedScope() {
        CertificateProperties goodProps = mockCertProps("good-cert");
        CertificateProperties badProps  = mockCertProps("bad-cert");
        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(certificateClient).when(spy).buildClient(eq("https://wi-kv.vault.azure.net/"), any());
        doReturn(List.of(goodProps, badProps)).when(spy).listProperties(certificateClient);
        KeyVaultCertificateWithPolicy goodCert = buildMockCert(
                "https://wi-kv.vault.azure.net/certificates/good-cert/v1",
                "CN=good.example.com", List.of("good.example.com"),
                OffsetDateTime.of(2025, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC),
                OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC),
                true);
        when(certificateClient.getCertificate("good-cert")).thenReturn(goodCert);
        when(certificateClient.getCertificate("bad-cert")).thenThrow(new RuntimeException("Forbidden"));

        com.certping.agent.discovery.DiscoveryResult result =
                spy.discoverWithFailedScopes(buildScopedMessage(SCOPE_JSON_WI));

        assertThat(result.certificates()).hasSize(1);
        assertThat(result.failedScopes()).singleElement().satisfies(f -> {
            assertThat(f.getScopeType()).isEqualTo(
                    com.certping.agent.model.message.DiscoveryFailedScope.ScopeType.AZURE_VAULT);
            assertThat(f.getScopeId()).isEqualTo("wi-kv");
            assertThat(f.getErrorCode()).isEqualTo("DISCOVERY_AZURE_KV_CERT_UNREADABLE");
            assertThat(f.getMessage()).contains("bad-cert");
        });
    }

    @Test
    void vaultNameIsTheFirstHostLabel() {
        assertThat(AzureKvDiscoveryAdapter.vaultName("https://my-vault.vault.azure.net/")).isEqualTo("my-vault");
        assertThat(AzureKvDiscoveryAdapter.vaultName("https://other.vault.azure.net")).isEqualTo("other");
    }

    @Test
    void discoverCertificates_mapsAllFields() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("my-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        // Use a far-future expiry so this test isn't time-bomb-sensitive.
        OffsetDateTime notBefore = OffsetDateTime.now(ZoneOffset.UTC).minusDays(30);
        OffsetDateTime notAfter  = OffsetDateTime.now(ZoneOffset.UTC).plusDays(60);

        KeyVaultCertificateWithPolicy cert = buildMockCert(
                "https://kv.vault.azure.net/certificates/my-cert/abc123",
                "CN=my.example.com", List.of("my.example.com", "alt.example.com"),
                notBefore, notAfter, true);

        when(certificateClient.getCertificate("my-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        DiscoveredCertEntry entry = result.get(0);
        assertThat(entry.getResourceId()).isEqualTo("https://kv.vault.azure.net/certificates/my-cert/abc123");
        assertThat(entry.getDomain()).isEqualTo("my.example.com");
        assertThat(entry.getSubjectDn()).isEqualTo("CN=my.example.com");
        assertThat(entry.getSanDomains()).containsExactlyInAnyOrder("my.example.com", "alt.example.com");
        // Enabled + valid expiry window → ISSUED (matches AWS ACM / UI filter vocabulary).
        assertThat(entry.getCertStatus()).isEqualTo("ISSUED");
        assertThat(entry.getNotBefore()).isEqualTo(notBefore.toString());
        assertThat(entry.getNotAfter()).isEqualTo(notAfter.toString());
        assertThat(entry.getCertType()).isEqualTo("IMPORTED");
        assertThat(entry.getInUseBy()).isEmpty();
        assertThat(entry.getKeyAlgorithm()).isEqualTo(CertificateKeyType.RSA.toString());
    }

    @Test
    void discoverCertificates_parsesSerialAndSignatureFromRawCert() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("serial-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        OffsetDateTime notBefore = OffsetDateTime.now(ZoneOffset.UTC).minusDays(1);
        OffsetDateTime notAfter  = OffsetDateTime.now(ZoneOffset.UTC).plusDays(30);

        KeyVaultCertificateWithPolicy cert = buildMockCert(
                "https://kv.vault.azure.net/certificates/serial-cert/v1",
                "CN=azure-test.example.com", List.of("azure-test.example.com"),
                notBefore, notAfter, true);
        // Self-signed test cert with serial 12345 (0x3039), signed SHA256withRSA.
        when(cert.getCer()).thenReturn(Base64.getDecoder().decode(TEST_CERT_DER_B64));

        when(certificateClient.getCertificate("serial-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        DiscoveredCertEntry entry = result.get(0);
        // Emitted as upper-case hex (no separators), matching the issuance format.
        assertThat(entry.getSerialNumber()).isEqualTo("3039");
        assertThat(entry.getSignatureAlgorithm()).isEqualTo("SHA256withRSA");
    }

    @Test
    void discoverCertificates_unparseableRawCert_leavesSerialNull() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("garbage-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        KeyVaultCertificateWithPolicy cert = buildMockCert(
                "https://kv.vault.azure.net/certificates/garbage-cert/v1",
                "CN=garbage.example.com", List.of(),
                OffsetDateTime.now(ZoneOffset.UTC).minusDays(1),
                OffsetDateTime.now(ZoneOffset.UTC).plusDays(30), true);
        when(cert.getCer()).thenReturn(new byte[] {1, 2, 3});   // not a valid certificate

        when(certificateClient.getCertificate("garbage-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getSerialNumber()).isNull();
        assertThat(result.get(0).getSignatureAlgorithm()).isNull();
    }

    /** Self-signed cert, CN=azure-test.example.com, serial 12345 (0x3039), SHA256withRSA. */
    private static final String TEST_CERT_DER_B64 =
            "MIICtzCCAZ8CAjA5MA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFmF6dXJlLXRlc3QuZXhhbXBsZS5jb20wHhcNMjYwNjIzMTg1OTQ2WhcNMjYwNjI0MTg1OTQ2WjAhMR8wHQYDVQQDDBZhenVyZS10ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZhDW4b/8FZD+qR0VtPAQfR2HlafoW325/CaVceAd9J+R4gbEKWNrSC0Gul5Nri6EO3h3e4BgqzLL1U9hm81/uuj9eAe82HC+iSfHExQqtLkKW4XVx4WndpTMJbWhjERgwol0JQiHd5w3lh52P/yFD4z79TBPg806DLfk4UoK27dV27H+jl3MDqwPqTaESsMPjvUTI8G/yrFLGs4ctLiw4kNF0A+IXKQPaFMur0DjQhJR3rLr0JlY+rwEmxDW+PwQqvOsz6pTiiYC4+BsSzS8yDPKvyIYcyH2QwzKEA0yudttht6uuzlEw2PlI9MTbs7VfltyAWG+FhzmvSkPPt9FQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAgG35I97gZX2PNeqqPKbtEf+BkNKxNPYmiY36Be0OYxZMztoJZk7VlYFHqlhPcytfYW02t+70zN066uBvuMtiXtjVxYv60prM7MGSAgIa0hpV1LlO6MIqXm5TABdzcEAZZv0jteEGMxzYcWsvMU8hk+M85m3d1071C7OkEujhnH9dANZVlmUBzFahehRlHZhtvTw1PpXiqCqspeik9M9DGrMHnER6XLdqePhpWEIXDW9kimPEbby6qAAXy/QwBtxSkeU9PW5pLtPIJ3BwQrSe340ItASaS+TjMOOP3ZAyFuXyJ5W/jDfpaP6gQMFzcmgFZCTO+gkrl9iF0dwYfmOtJ";

    @Test
    void discoverCertificates_disabledCert_hasInactiveStatus() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("disabled-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        KeyVaultCertificateWithPolicy cert = buildMockCert(
                "https://kv.vault.azure.net/certificates/disabled-cert/v1",
                "CN=disabled.example.com", List.of(),
                null, null, false);

        when(certificateClient.getCertificate("disabled-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        // disabled flag → INACTIVE (was "DISABLED" before the UI-aligned mapping).
        assertThat(result.get(0).getCertStatus()).isEqualTo("INACTIVE");
    }

    @Test
    void discoverCertificates_expiredCert_hasExpiredStatus() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("expired-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        OffsetDateTime notBefore = OffsetDateTime.now(ZoneOffset.UTC).minusDays(400);
        OffsetDateTime notAfter  = OffsetDateTime.now(ZoneOffset.UTC).minusDays(1);

        KeyVaultCertificateWithPolicy cert = buildMockCert(
                "https://kv.vault.azure.net/certificates/expired-cert/v1",
                "CN=expired.example.com", List.of("expired.example.com"),
                notBefore, notAfter, true);

        when(certificateClient.getCertificate("expired-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        // Past expiry trumps the enabled flag.
        assertThat(result.get(0).getCertStatus()).isEqualTo("EXPIRED");
    }

    @Test
    void discoverCertificates_enabledButNoExpiry_hasUnknownStatus() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("no-expiry-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        KeyVaultCertificateWithPolicy cert = buildMockCert(
                "https://kv.vault.azure.net/certificates/no-expiry-cert/v1",
                "CN=no-expiry.example.com", List.of("no-expiry.example.com"),
                null, null, true);

        when(certificateClient.getCertificate("no-expiry-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        // enabled=true but no expiry to compare against → UNKNOWN (don't lie about validity).
        assertThat(result.get(0).getCertStatus()).isEqualTo("UNKNOWN");
    }

    @Test
    void discoverCertificates_nullDatesHandledGracefully() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("null-dates-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        KeyVaultCertificateWithPolicy cert = buildMockCert(
                "https://kv.vault.azure.net/certificates/null-dates-cert/v1",
                "CN=test.example.com", List.of("test.example.com"),
                null, null, true);

        when(certificateClient.getCertificate("null-dates-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getNotBefore()).isNull();
        assertThat(result.get(0).getNotAfter()).isNull();
    }

    @Test
    void discoverCertificates_noPolicyFallsBackGracefully() {
        AzureKvDiscoveryAdapter spy = spy(adapter);

        CertificateProperties props = mockCertProps("no-policy-cert");
        doReturn(List.of(props)).when(spy).listProperties(certificateClient);

        KeyVaultCertificateWithPolicy cert = mock(KeyVaultCertificateWithPolicy.class);
        CertificateProperties certProps = mock(CertificateProperties.class);

        when(cert.getId()).thenReturn("https://kv.vault.azure.net/certificates/no-policy-cert/v1");
        when(cert.getProperties()).thenReturn(certProps);
        when(cert.getPolicy()).thenReturn(null);
        when(certProps.isEnabled()).thenReturn(true);
        when(certProps.getNotBefore()).thenReturn(null);
        when(certProps.getExpiresOn()).thenReturn(null);

        when(certificateClient.getCertificate("no-policy-cert")).thenReturn(cert);

        List<DiscoveredCertEntry> result = spy.discoverCertificates(certificateClient, "org-1");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getDomain()).isNull();
        assertThat(result.get(0).getSubjectDn()).isNull();
        assertThat(result.get(0).getKeyAlgorithm()).isNull();
    }

    // ------------------------------------------------------------------ //
    //  End-to-end legacy discover still reaches discoverCertificates
    // ------------------------------------------------------------------ //

    @Test
    void discover_legacy_fullFlow_withValidJson() {
        when(secretStore.read(anyString())).thenReturn(VALID_CRED_JSON);

        AzureKvDiscoveryAdapter spy = spy(adapter);
        doReturn(certificateClient).when(spy).buildClient(eq("https://my-kv.vault.azure.net/"), any());
        doReturn(List.of()).when(spy).listProperties(certificateClient);

        assertThat(spy.discover(buildLegacyMessage())).isEmpty();
        verify(azureCredentialResolver, never()).resolve(any(), any(), any(), anyString());
    }

    // ------------------------------------------------------------------ //
    //  Helpers
    // ------------------------------------------------------------------ //

    private CertDiscoveryMessage buildLegacyMessage() {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setOrganizationId("org-1");
        msg.setTargetType(TargetType.AZURE_KV);
        msg.setDeploymentCredHandle("https://kv-test.vault.azure.net/secrets/azure-kv-cred");
        return msg;
    }

    private CertDiscoveryMessage buildScopedMessage(String credentialScopeJson) {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setOrganizationId("org-1");
        msg.setTargetType(TargetType.AZURE_KV);
        msg.setDeploymentCredHandle("https://kv-test.vault.azure.net/secrets/azure-kv-cred");
        msg.setCredentialScopeJson(credentialScopeJson);
        return msg;
    }

    private CertificateProperties mockCertProps(String name) {
        CertificateProperties props = mock(CertificateProperties.class);
        when(props.getName()).thenReturn(name);
        return props;
    }

    private KeyVaultCertificateWithPolicy buildMockCert(
            String id, String subject,
            List<String> dnsNames,
            OffsetDateTime notBefore, OffsetDateTime notAfter,
            boolean enabled) {

        KeyVaultCertificateWithPolicy cert = mock(KeyVaultCertificateWithPolicy.class);
        CertificateProperties props = mock(CertificateProperties.class);
        CertificatePolicy policy    = mock(CertificatePolicy.class);
        SubjectAlternativeNames sans = mock(SubjectAlternativeNames.class);

        when(cert.getId()).thenReturn(id);
        when(cert.getProperties()).thenReturn(props);
        when(cert.getPolicy()).thenReturn(policy);

        when(props.isEnabled()).thenReturn(enabled);
        when(props.getNotBefore()).thenReturn(notBefore);
        when(props.getExpiresOn()).thenReturn(notAfter);

        when(policy.getSubject()).thenReturn(subject);
        when(policy.getIssuerName()).thenReturn("Self");
        when(policy.getKeyType()).thenReturn(CertificateKeyType.RSA);
        when(policy.getSubjectAlternativeNames()).thenReturn(sans);
        when(sans.getDnsNames()).thenReturn(dnsNames);
        when(sans.getEmails()).thenReturn(List.of());

        return cert;
    }
}
