// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static com.certping.agent.ssl.ejbca.LocalHttpsServer.Response.of;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EjbcaClient")
class EjbcaClientTest {

    private LocalHttpsServer server;
    private AgentProperties properties;
    private CountingSecretStore secretStore;
    private EjbcaClient client;

    @BeforeEach
    void setUp() throws Exception {
        server = new LocalHttpsServer();
        properties = new AgentProperties();
        AgentProperties.EjbcaProperties config = properties.getEjbca();
        config.setEnabled(true);
        config.setCredentialPath("kv://ejbca");
        config.setRequestTimeoutSeconds(10);

        secretStore = new CountingSecretStore(credentialJson());
        client = new EjbcaClient(properties, secretStore, JsonMapper.builderWithJackson2Defaults().build());
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    @DisplayName("enrolls over real TLS with hostname verification on")
    void enrollsOverTls() {
        server.respond(of(201, "{\"certificate\":\"AAA\",\"serial_number\":\"1F\"}"));

        JsonNode response = client.pkcs10Enroll(Map.of("username", "device-1"));

        assertThat(response.path("serial_number").asString()).isEqualTo("1F");
        assertThat(server.requestedPaths())
                .containsExactly("/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll");
    }

    @Test
    @DisplayName("reads the credential once and reuses the session")
    void credentialIsReadOnce() {
        server.respond(of(200, "{\"ok\":true}"));

        client.pkcs10Enroll(Map.of());
        client.pkcs10Enroll(Map.of());

        // Re-reading per request would put a vault round trip in the synchronous signing path.
        assertThat(secretStore.reads()).isEqualTo(1);
    }

    @Test
    @DisplayName("reloads the credential once on 401 and succeeds on the retry")
    void reloadsCredentialOnceOn401() {
        server.respond(of(401, "{\"error\":\"stale\"}"), of(200, "{\"ok\":true}"));

        client.pkcs10Enroll(Map.of());

        assertThat(server.callCount()).isEqualTo(2);
        // Picks up a rotated credential without a restart.
        assertThat(secretStore.reads()).isEqualTo(2);
    }

    @Test
    @DisplayName("retries exactly once, then gives up")
    void retriesOnlyOnce() {
        server.respond(of(403, "{\"message\":\"nope\"}"));

        assertThatThrownBy(() -> client.pkcs10Enroll(Map.of()))
                .isInstanceOf(PermanentAgentException.class);

        assertThat(server.callCount()).as("one attempt plus one retry, never a loop").isEqualTo(2);
    }

    @Test
    @DisplayName("probes version without sending any authorization")
    void probeVersionReadsRevision() {
        server.respond(of(200,
                "{\"status\":\"OK\",\"version\":\"1.0\",\"revision\":\"EJBCA 9.3.7 Community\"}"));

        assertThat(client.probeVersion()).isEqualTo("EJBCA 9.3.7 Community");
        assertThat(server.requestedPaths())
                .containsExactly("/ejbca/ejbca-rest-api/v1/certificate/status");
    }

    @Test
    @DisplayName("falls back to version when the CA reports no revision string")
    void probeVersionFallsBackToVersion() {
        server.respond(of(200, "{\"status\":\"OK\",\"version\":\"1.0\"}"));

        assertThat(client.probeVersion()).isEqualTo("1.0");
    }

    @Test
    @DisplayName("surfaces a redirect instead of following it and losing the POST body")
    void redirectIsSurfaced() {
        server.respond(new LocalHttpsServer.Response(302, "", "https://elsewhere/x"));

        assertThatThrownBy(() -> client.pkcs10Enroll(Map.of()))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_UNEXPECTED_REDIRECT"));
    }

    @Test
    @DisplayName("rejects a non-JSON success body")
    void nonJsonBodyIsRejected() {
        server.respond(of(200, "<html>not json</html>"));

        assertThatThrownBy(() -> client.pkcs10Enroll(Map.of()))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_RESPONSE_INVALID"));
    }

    @Test
    @DisplayName("fails clearly when neither credential path nor credentials-json is configured")
    void missingCredentialPathIsRejected() {
        properties.getEjbca().setCredentialPath("  ");

        assertThatThrownBy(() -> client.pkcs10Enroll(Map.of()))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_CONFIG_MISSING"));
    }

    @Test
    @DisplayName("uses credentials-json directly without touching the secret store when set")
    void usesCredentialsJsonWithoutSecretStore() {
        properties.getEjbca().setCredentialPath(null);
        properties.getEjbca().setCredentialsJson(credentialJson());
        server.respond(of(200, "{\"ok\":true}"));

        client.pkcs10Enroll(Map.of());

        assertThat(secretStore.reads()).isEqualTo(0);
    }

    @Test
    @DisplayName("prefers credentials-json over credential-path when both are set")
    void credentialsJsonTakesPrecedenceOverCredentialPath() {
        properties.getEjbca().setCredentialsJson(credentialJson());
        server.respond(of(200, "{\"ok\":true}"));

        client.pkcs10Enroll(Map.of());

        assertThat(secretStore.reads()).isEqualTo(0);
    }

    @Test
    @DisplayName("invalidate forces the next call to re-read the credential")
    void invalidateForcesReload() {
        server.respond(of(200, "{\"ok\":true}"));
        client.pkcs10Enroll(Map.of());

        client.invalidate();
        client.pkcs10Enroll(Map.of());

        assertThat(secretStore.reads()).isEqualTo(2);
    }

    @Test
    @DisplayName("reports the connected endpoint and auth method, and no secrets")
    void describesConnectionWithoutSecrets() {
        server.respond(of(200, "{\"ok\":true}"));
        client.pkcs10Enroll(Map.of());

        EjbcaClient.ConnectionInfo info = client.describeConnection();

        assertThat(info.baseUrl()).isEqualTo(server.baseUrl());
        assertThat(info.authMethod()).isEqualTo("CLIENT_CERT");
        assertThat(info.toString()).doesNotContain("p12-password");
    }

    @Test
    @DisplayName("describeConnection is null before a session exists")
    void describeConnectionNullBeforeUse() {
        assertThat(client.describeConnection()).isNull();
    }

    @Test
    @DisplayName("a TLS trust mismatch is permanent, not retried forever")
    void untrustedServerIsPermanent() throws Exception {
        // Point at the server but trust a different CA — the shape of a wrong serverCaChainPem.
        try (LocalHttpsServer other = new LocalHttpsServer()) {
            secretStore.setValue(credentialJson(server.baseUrl(), other.caPem()));
            client.invalidate();
            server.respond(of(200, "{\"ok\":true}"));

            assertThatThrownBy(() -> client.pkcs10Enroll(Map.of()))
                    .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                            assertThat(e.getErrorCode()).isEqualTo("EJBCA_TLS_HANDSHAKE_FAILED"));
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private String credentialJson() {
        return credentialJson(server.baseUrl(), server.caPem());
    }

    private String credentialJson(String baseUrl, String caPem) {
        return """
                {"authMethod":"CLIENT_CERT","baseUrl":"%s",
                 "clientP12Base64":"%s","clientP12Password":"p12-password",
                 "serverCaChainPem":"%s"}"""
                .formatted(baseUrl, TestP12.base64(), caPem.replace("\n", "\\n"));
    }

    private static final class CountingSecretStore implements SecretStore {
        private final AtomicInteger reads = new AtomicInteger();
        private volatile String value;

        CountingSecretStore(String value) {
            this.value = value;
        }

        void setValue(String value) {
            this.value = value;
        }

        int reads() {
            return reads.get();
        }

        @Override public String read(String handle) { reads.incrementAndGet(); return value; }
        @Override public String create(String name, String v) { throw new UnsupportedOperationException(); }
        @Override public String update(String handle, String v) { throw new UnsupportedOperationException(); }
        @Override public void delete(String handle) { throw new UnsupportedOperationException(); }
        @Override public boolean isOwnedByThisAgent(String handle) { return false; }
        @Override public String handleFor(String name) { return name; }
        @Override public SecretStoreProvider provider() { return null; }
    }
}
