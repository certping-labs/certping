// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.AkamaiCpsDeploymentCredential;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Tests {@link AkamaiCpsAuthService} — credential parsing, KV secret round-trip,
 * and the EdgeGrid HTTP client factory.
 */
@ExtendWith(MockitoExtension.class)
class AkamaiCpsAuthServiceTest {

    @Mock private SecretStore secretStore;

    private AkamaiCpsAuthService service;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = JsonMapper.builderWithJackson2Defaults().build();
        service = new AkamaiCpsAuthService(secretStore, objectMapper);
    }

    // ── parseCredential: happy + missing-field variants ──────────────────

    @Test
    void parseCredential_validJson_returnsPopulated() {
        String json = validCredentialJson();
        AkamaiCpsDeploymentCredential cred = service.parseCredential(json);
        assertThat(cred.getHost()).isEqualTo("akaa-example.luna.akamaiapis.net");
        assertThat(cred.getEnrollments()).isNotEmpty();
    }

    @Test
    void parseCredential_missingHost_throwsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("""
                {"clientToken":"ct","accessToken":"at","clientSecret":"cs","enrollments":[{"enrollmentId":"1"}]}"""))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("host");
    }

    @Test
    void parseCredential_missingClientToken_throwsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("""
                {"host":"h","accessToken":"at","clientSecret":"cs","enrollments":[{"enrollmentId":"1"}]}"""))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("clientToken");
    }

    @Test
    void parseCredential_missingAccessToken_throwsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("""
                {"host":"h","clientToken":"ct","clientSecret":"cs","enrollments":[{"enrollmentId":"1"}]}"""))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("accessToken");
    }

    @Test
    void parseCredential_missingClientSecret_throwsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("""
                {"host":"h","clientToken":"ct","accessToken":"at","enrollments":[{"enrollmentId":"1"}]}"""))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("clientSecret");
    }

    @Test
    void parseCredential_blankClientToken_throwsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("""
                {"host":"h","clientToken":"   ","accessToken":"at","clientSecret":"cs","enrollments":[{"enrollmentId":"1"}]}"""))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void parseCredential_missingEnrollments_throwsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("""
                {"host":"h","clientToken":"ct","accessToken":"at","clientSecret":"cs"}"""))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("enrollments");
    }

    @Test
    void parseCredential_emptyEnrollments_throwsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("""
                {"host":"h","clientToken":"ct","accessToken":"at","clientSecret":"cs","enrollments":[]}"""))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("enrollments");
    }

    @Test
    void parseCredential_malformedJson_wrappedAsInvalid() {
        assertThatThrownBy(() -> service.parseCredential("not-json"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("Failed to parse Akamai");
    }

    // ── loadCredential ────────────────────────────────────────────────────

    @Test
    void loadCredential_readsFromKvAndParses() {
        when(secretStore.read("https://kv.vault.azure.net/secrets/akamai")).thenReturn(validCredentialJson());
        AkamaiCpsDeploymentCredential cred = service.loadCredential("https://kv.vault.azure.net/secrets/akamai");
        assertThat(cred.getHost()).isNotBlank();
    }

    // ── baseUrl / requireField ────────────────────────────────────────────

    @Test
    void baseUrl_stringHost_returnsHttpsPrefix() {
        assertThat(service.baseUrl("akamai.example.com"))
                .isEqualTo("https://akamai.example.com");
    }

    @Test
    void baseUrl_credential_returnsHttpsPrefix() {
        AkamaiCpsDeploymentCredential cred = service.parseCredential(validCredentialJson());
        assertThat(service.baseUrl(cred))
                .isEqualTo("https://akaa-example.luna.akamaiapis.net");
    }

    @Test
    void baseUrl_blankHost_throwsInvalid() {
        assertThatThrownBy(() -> service.baseUrl("  "))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void baseUrl_nullHost_throwsInvalid() {
        assertThatThrownBy(() -> service.baseUrl((String) null))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── buildClient (credential + KV-secret variants) ─────────────────────

    @Test
    void buildClient_fromCredential_returnsClosableClient() throws Exception {
        AkamaiCpsDeploymentCredential cred = service.parseCredential(validCredentialJson());
        try (var client = service.buildClient(cred)) {
            assertThat(client).isNotNull();
        }
    }

    @Test
    void buildClient_fromKvSecret_returnsClosableClient() throws Exception {
        AkamaiKvSecret kv = new AkamaiKvSecret("ct", "at", "cs");
        try (var client = service.buildClient(kv, "akamai.example.com")) {
            assertThat(client).isNotNull();
        }
    }

    @Test
    void buildClient_kvSecretMissingClientToken_throwsInvalid() {
        AkamaiKvSecret kv = new AkamaiKvSecret(null, "at", "cs");
        assertThatThrownBy(() -> service.buildClient(kv, "akamai.example.com"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("clientToken");
    }

    // ── parseKvSecret ─────────────────────────────────────────────────────

    @Test
    void parseKvSecret_validJson_returnsRecord() {
        when(secretStore.read("kv-path"))
                .thenReturn("{\"clientToken\":\"ct\",\"accessToken\":\"at\",\"clientSecret\":\"cs\"}");
        AkamaiKvSecret kv = service.parseKvSecret("kv-path");
        assertThat(kv.clientToken()).isEqualTo("ct");
        assertThat(kv.accessToken()).isEqualTo("at");
        assertThat(kv.clientSecret()).isEqualTo("cs");
    }

    @Test
    void parseKvSecret_kvThrows_wrappedAsInvalid() {
        when(secretStore.read("bad-path")).thenThrow(new RuntimeException("not found"));
        assertThatThrownBy(() -> service.parseKvSecret("bad-path"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("Failed to parse Akamai KV secret");
    }

    @Test
    void parseKvSecret_malformedJson_wrappedAsInvalid() {
        when(secretStore.read("kv-path")).thenReturn("not-json");
        assertThatThrownBy(() -> service.parseKvSecret("kv-path"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private String validCredentialJson() {
        return """
                {
                  "host": "akaa-example.luna.akamaiapis.net",
                  "clientToken": "akab-client-token",
                  "accessToken": "akab-access-token",
                  "clientSecret": "akab-client-secret",
                  "enrollments": [{"enrollmentId":"12345"}]
                }
                """;
    }
}
