// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.message.CaConnectorHealth;
import com.certping.agent.model.message.CaConnectorStatus;
import com.certping.agent.ssl.smallstep.SmallstepSigningService;
import com.certping.agent.ssl.smallstep.SmallstepRevocationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SmallstepCaHealthProbeTest {
    private AgentProperties properties;
    private SmallstepSigningService signingService;
    private SmallstepRevocationService revocationService;
    private SmallstepCaHealthProbe probe;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getSmallstep().setEnabled(true);
        properties.getSmallstep().setCredentialPath("kv://smallstep");
        properties.getSmallstep().setBaseUrl("https://step.internal");
        signingService = mock(SmallstepSigningService.class);
        revocationService = mock(SmallstepRevocationService.class);
        probe = new SmallstepCaHealthProbe(properties, signingService, revocationService);
    }

    @Test
    void reportsHealthyVersionAndVerifiedProvisioner() {
        when(signingService.probeVersion()).thenReturn("0.30.2");
        when(signingService.connectedEndpoint()).thenReturn("https://step.internal");
        when(signingService.provisionerName()).thenReturn("certping-agent");

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.HEALTHY.name());
        assertThat(health.getCaProvider()).isEqualTo("SMALLSTEP");
        assertThat(health.getAuthMethod()).isEqualTo("JWK_PROVISIONER_TOKEN");
        assertThat(health.getProduct().getVersion()).isEqualTo("0.30.2");
        assertThat(health.getCapabilities())
                .contains("SIGN_CSR", "REVOKE_CERTIFICATE", "CHECK_REVOCATION");
        verify(revocationService).verifyReady();
        assertThat(health.getProfiles()).singleElement().satisfies(profile -> {
            assertThat(profile.getKind()).isEqualTo("PROVISIONER");
            assertThat(profile.getName()).isEqualTo("certping-agent");
            assertThat(profile.getVerified()).isTrue();
        });
    }

    @Test
    void missingCredentialIsUnconfiguredWithoutNetworkCall() {
        properties.getSmallstep().setCredentialPath(" ");

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.UNCONFIGURED.name());
        verify(signingService, never()).probeVersion();
        verify(revocationService, never()).verifyReady();
    }

    @Test
    void credentialsJsonAloneIsSufficientToProbe() {
        properties.getSmallstep().setCredentialPath(null);
        properties.getSmallstep().setCredentialsJson("{}");
        when(signingService.probeVersion()).thenReturn("0.30.2");
        when(signingService.connectedEndpoint()).thenReturn("https://step.internal");
        when(signingService.provisionerName()).thenReturn("certping-agent");

        CaConnectorHealth health = probe.probe();

        assertThat(health.getStatus()).isEqualTo(CaConnectorStatus.HEALTHY.name());
        verify(signingService).probeVersion();
        verify(revocationService).verifyReady();
    }

    @Test
    void mapsAuthenticationAndNetworkFailuresDifferently() {
        when(signingService.probeVersion())
                .thenThrow(new PermanentAgentException("SMALLSTEP_AUTH_FAILED", "rejected"))
                .thenThrow(new TransientAgentException("SMALLSTEP_NETWORK_ERROR", "offline"));

        assertThat(probe.probe().getStatus()).isEqualTo(CaConnectorStatus.UNAUTHORIZED.name());
        assertThat(probe.probe().getStatus()).isEqualTo(CaConnectorStatus.UNREACHABLE.name());
    }

    @Test
    void reportsMissingCrlAsUnconfigured() {
        when(signingService.probeVersion()).thenReturn("0.30.2");
        org.mockito.Mockito.doThrow(new PermanentAgentException(
                        "SMALLSTEP_CRL_NOT_CONFIGURED", "enable CRLs"))
                .when(revocationService).verifyReady();

        assertThat(probe.probe().getStatus()).isEqualTo(CaConnectorStatus.UNCONFIGURED.name());
    }
}
