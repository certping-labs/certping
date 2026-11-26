// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.message.CaConnectorHealth;
import com.certping.agent.model.message.CaConnectorStatus;
import com.certping.agent.model.message.CaHealthIssue;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("EjbcaCaHealthProbe")
class EjbcaCaHealthProbeTest {

    private static final String LIVE_REVISION =
            "EJBCA 9.3.7 Community (afce321eed98ab06bd8cc78e89fc50b73a5b8db4)";

    private AgentProperties properties;
    private EjbcaSigningService signingService;
    private EjbcaCaHealthProbe probe;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        AgentProperties.EjbcaProperties config = properties.getEjbca();
        config.setEnabled(true);
        config.setCredentialPath("kv://ejbca");
        config.setBaseUrl("https://ejbca.internal.example.com:8443");
        config.setCaName("ManagementCA");
        config.setCertificateProfileName("ENDUSER");
        config.setEndEntityProfileName("EMPTY");

        signingService = mock(EjbcaSigningService.class);
        probe = new EjbcaCaHealthProbe(properties, signingService);
    }

    @Test
    @DisplayName("reports HEALTHY and parses version and edition from the live status string")
    void healthyReportsProductInfo() {
        when(signingService.probeVersion()).thenReturn(LIVE_REVISION);

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.HEALTHY.name());
        assertThat(health.getCaProvider()).isEqualTo("EJBCA");
        assertThat(health.getProduct().getName()).isEqualTo("EJBCA");
        assertThat(health.getProduct().getVersion()).isEqualTo("9.3.7");
        assertThat(health.getProduct().getEdition()).isEqualTo("Community");
        assertThat(health.getIssues()).isEmpty();
        assertThat(health.getLatencyMs()).isNotNull();
        assertThat(health.getCapabilities()).containsExactly("SIGN_CSR");
    }

    @Test
    @DisplayName("reports the configured CA and profile names, unverified")
    void reportsConfiguredProfiles() {
        when(signingService.probeVersion()).thenReturn(LIVE_REVISION);

        CaConnectorHealth health = probe.probe();

        // Unverified because EJBCA Community exposes no endpoint to enumerate profiles — the
        // agent can say what it is configured to use, not that any of it exists.
        assertThat(health.getProfiles())
                .extracting("kind", "name", "verified")
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("CA", "ManagementCA", false),
                        org.assertj.core.groups.Tuple.tuple("CERTIFICATE_PROFILE", "ENDUSER", false),
                        org.assertj.core.groups.Tuple.tuple("END_ENTITY_PROFILE", "EMPTY", false));
    }

    @Test
    @DisplayName("reports UNCONFIGURED without probing when the connector is disabled")
    void disabledIsUnconfigured() {
        properties.getEjbca().setEnabled(false);

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.UNCONFIGURED.name());
        assertThat(health.getEnabled()).isFalse();
        assertThat(health.getIssues()).isEmpty();
        assertThat(health.getLatencyMs()).isNull();
    }

    @Test
    @DisplayName("lists every missing required setting rather than only the first")
    void missingConfigurationIsEnumerated() {
        properties.getEjbca().setCaName("  ");
        properties.getEjbca().setEndEntityProfileName(null);

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.UNCONFIGURED.name());
        assertThat(health.getIssues())
                .hasSize(2)
                .allSatisfy(issue -> assertThat(issue.getCode()).isEqualTo("CA_CONFIG_MISSING"))
                .extracting(CaHealthIssue::getMessage)
                .anySatisfy(message -> assertThat(message).contains("ca-name"))
                .anySatisfy(message -> assertThat(message).contains("end-entity-profile-name"));
    }

    @Test
    @DisplayName("flags missing configuration when neither credential-path nor credentials-json is set")
    void missingCredentialSourceIsFlagged() {
        properties.getEjbca().setCredentialPath(null);

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.UNCONFIGURED.name());
        assertThat(health.getIssues())
                .extracting(CaHealthIssue::getMessage)
                .anySatisfy(message -> assertThat(message).contains("credential-path")
                        .contains("credentials-json"));
    }

    @Test
    @DisplayName("credentials-json alone satisfies the credential requirement")
    void credentialsJsonAloneIsSufficient() {
        properties.getEjbca().setCredentialPath(null);
        properties.getEjbca().setCredentialsJson("{}");
        when(signingService.probeVersion()).thenReturn("EJBCA 9.3.7 Community");

        CaConnectorHealth health = probe.probe();

        assertThat(health.getIssues())
                .noneSatisfy(issue -> assertThat(issue.getMessage()).contains("credentials-json"));
    }

    @ParameterizedTest(name = "{0} maps to {1}")
    @CsvSource({
            "EJBCA_REST_DISABLED,           UNREACHABLE",
            "EJBCA_TLS_HANDSHAKE_FAILED,    UNREACHABLE",
            "EJBCA_NETWORK_ERROR,           UNREACHABLE",
            "EJBCA_AUTH_FAILED,             UNAUTHORIZED",
            "EJBCA_OAUTH_REJECTED,          UNAUTHORIZED",
            "EJBCA_CREDENTIAL_NOT_PRESENTED,UNAUTHORIZED",
            "EJBCA_CREDENTIAL_INVALID,      UNCONFIGURED",
            "SOMETHING_ELSE,                ERROR",
    })
    @DisplayName("distinguishes unreachable from unauthorized, because the operator fix differs")
    void errorCodesMapToDistinctStatuses(String errorCode, String expectedStatus) {
        when(signingService.probeVersion())
                .thenThrow(new PermanentAgentException(errorCode, "probe failed"));

        assertThat(probe.probe().getStatus()).isEqualTo(expectedStatus);
    }

    @Test
    @DisplayName("attaches remediation for the failure that ships broken by default")
    void restDisabledCarriesRemediation() {
        when(signingService.probeVersion()).thenThrow(
                new PermanentAgentException("EJBCA_REST_DISABLED", "REST protocol is disabled"));

        CaHealthIssue issue = probe.probe().getIssues().get(0);

        assertThat(issue.getRemediation()).contains("config protocols enable");
    }

    @Test
    @DisplayName("warns but stays usable on an out-of-support CA version")
    void oldVersionIsDegradedNotFailed() {
        when(signingService.probeVersion()).thenReturn("EJBCA 7.9.0 Community (abc123)");

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.DEGRADED.name());
        assertThat(health.getIssues()).singleElement().satisfies(issue -> {
            assertThat(issue.getSeverity()).isEqualTo("WARN");
            assertThat(issue.getCode()).isEqualTo("CA_VERSION_UNSUPPORTED");
        });
    }

    @Test
    @DisplayName("treats the supported floor itself as healthy")
    void supportedFloorIsHealthy() {
        when(signingService.probeVersion()).thenReturn("EJBCA 9.3.3 Enterprise (abc123)");

        assertThat(probe.probe().getStatus()).isEqualTo(CaConnectorStatus.HEALTHY.name());
    }

    @Test
    @DisplayName("never throws, whatever the probe does")
    void unexpectedFailureIsContained() {
        when(signingService.probeVersion()).thenThrow(new IllegalStateException("boom"));

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.ERROR.name());
        assertThat(health.getIssues()).singleElement()
                .satisfies(issue -> assertThat(issue.getCode()).isEqualTo("CA_PROBE_FAILED"));
    }

    @Test
    @DisplayName("keeps an unparseable version string as raw rather than discarding it")
    void unparseableVersionKeepsRaw() {
        when(signingService.probeVersion()).thenReturn("something unexpected");

        assertThat(probe.probe().getProduct().getRaw()).isEqualTo("something unexpected");
    }

    @Test
    @DisplayName("a transient failure is still reported, not swallowed")
    void transientFailureIsReported() {
        when(signingService.probeVersion())
                .thenThrow(new TransientAgentException("EJBCA_NETWORK_ERROR", "connect timed out"));

        assertThat(probe.probe().getStatus()).isEqualTo(CaConnectorStatus.UNREACHABLE.name());
    }
}
