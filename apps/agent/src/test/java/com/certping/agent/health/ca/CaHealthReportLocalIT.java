// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.CaConnectorHealth;
import com.certping.agent.model.message.CaConnectorStatus;
import com.certping.agent.model.message.CaHealthReport;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import com.certping.agent.ssl.ejbca.EjbcaTestSupport;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Builds and publishes a CA health report using the real collaborators against the live local
 * EJBCA, and asserts on the JSON the server would actually receive.
 *
 * <p>Skips when {@code local/ejbca/generated/credential.json} is absent. Only the secret store
 * and the message sender are substituted — everything between the probe and the wire is production
 * code, including the serialization.
 */
@DisplayName("CA health report against local EJBCA (integration)")
class CaHealthReportLocalIT {

    private static final Path CREDENTIAL_FILE =
            Path.of("local", "ejbca", "generated", "credential.json");

    private static AgentProperties properties;
    private static SecretStore secretStore;

    @BeforeAll
    static void setUp() throws Exception {
        assumeTrue(Files.exists(CREDENTIAL_FILE),
                "local EJBCA credential not found — run local/ejbca/bootstrap.sh first");

        secretStore = new FixedSecretStore(Files.readString(CREDENTIAL_FILE));
        properties = new AgentProperties();
        AgentProperties.EjbcaProperties config = properties.getEjbca();
        config.setEnabled(true);
        config.setCredentialPath("local://ejbca-credential");
        config.setCaName("ManagementCA");
        config.setCertificateProfileName("ENDUSER");
        config.setEndEntityProfileName("EMPTY");
        properties.setOrganizationId("local-tenant-001");
    }

    @Test
    @DisplayName("reports the live CA as healthy with its real version and edition")
    void reportsLiveCaAsHealthy() {
        CaHealthReport report = buildReport();

        assertThat(report.getReportVersion()).isEqualTo(1);
        assertThat(report.getOrganizationId()).isEqualTo("local-tenant-001");
        assertThat(report.getConnectors()).hasSize(1);

        CaConnectorHealth ejbca = report.getConnectors().get(0);
        assertThat(ejbca.getStatus()).isEqualTo(CaConnectorStatus.HEALTHY.name());
        assertThat(ejbca.getCaProvider()).isEqualTo("EJBCA");
        assertThat(ejbca.getEnabled()).isTrue();
        assertThat(ejbca.getProduct().getName()).isEqualTo("EJBCA");
        assertThat(ejbca.getProduct().getVersion()).isNotBlank();
        assertThat(ejbca.getProduct().getEdition()).isIn("Community", "Enterprise");
        assertThat(ejbca.getLatencyMs()).isNotNull().isGreaterThanOrEqualTo(0L);
        assertThat(ejbca.getIssues()).isEmpty();
        assertThat(ejbca.getProfiles()).hasSize(3);
    }

    @Test
    @DisplayName("publishes the report through the sender as AGENT_CA_HEALTH_REPORT")
    void publishesThroughTheSender() {
        AgentMessageSender sender = mock(AgentMessageSender.class);
        publisher(sender).publishCaHealthReport();

        ArgumentCaptor<CaHealthReport> captor = ArgumentCaptor.forClass(CaHealthReport.class);
        verify(sender).sendCaHealthReport(captor.capture());
        assertThat(captor.getValue().getConnectors()).hasSize(1);
    }

    @Test
    @DisplayName("serializes to a provider-neutral payload with no credentials in it")
    void payloadIsNeutralAndCarriesNoSecrets() throws Exception {
        String json = JsonMapper.builderWithJackson2Defaults().build()
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(buildReport());

        System.out.println("=== AGENT_CA_HEALTH_REPORT payload ===\n" + json);

        // Shape a Smallstep or DigiCert One connector would fill identically.
        assertThat(json)
                .contains("\"reportVersion\"")
                .contains("\"caProvider\" : \"EJBCA\"")
                .contains("\"status\" : \"HEALTHY\"")
                .contains("\"capabilities\"")
                .contains("\"profiles\"");

        // Assert on the secret VALUES, not their field names: checking for "clientP12Base64"
        // would pass while leaking the key it labels.
        tools.jackson.databind.JsonNode credential =
                JsonMapper.builderWithJackson2Defaults().build().readTree(Files.readString(CREDENTIAL_FILE));
        String p12 = credential.path("clientP12Base64").asString("");
        String p12Password = credential.path("clientP12Password").asString("");
        assertThat(p12).as("fixture must actually contain a P12 for this test to mean anything")
                .isNotBlank();

        assertThat(json)
                .as("the client private key must never reach cert-manager")
                .doesNotContain(p12)
                .doesNotContain(p12.substring(0, Math.min(64, p12.length())));
        assertThat(json)
                .as("the P12 passphrase must never reach cert-manager")
                .doesNotContain(p12Password);
        assertThat(json).doesNotContain("clientP12Base64").doesNotContain("clientSecret");
    }

    // ── wiring ────────────────────────────────────────────────────────────────

    private CaHealthReport buildReport() {
        return publisher(mock(AgentMessageSender.class)).buildReport();
    }

    private CaHealthReportPublisher publisher(AgentMessageSender sender) {
        return new CaHealthReportPublisher(properties, sender, List.of(realProbe()));
    }

    /** Real probe over a real client over the real CA — only the vault is substituted. */
    private EjbcaCaHealthProbe realProbe() {
        EjbcaSigningService signingService =
                EjbcaTestSupport.signingService(properties, secretStore);
        return new EjbcaCaHealthProbe(properties, signingService);
    }

    private record FixedSecretStore(String value) implements SecretStore {
        @Override public String read(String handle) { return value; }
        @Override public String create(String name, String v) { throw new UnsupportedOperationException(); }
        @Override public String update(String handle, String v) { throw new UnsupportedOperationException(); }
        @Override public void delete(String handle) { throw new UnsupportedOperationException(); }
        @Override public boolean isOwnedByThisAgent(String handle) { return false; }
        @Override public String handleFor(String name) { return name; }
        @Override public SecretStoreProvider provider() { return null; }
    }
}
