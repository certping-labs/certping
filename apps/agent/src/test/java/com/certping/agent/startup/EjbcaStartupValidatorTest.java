// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.startup;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("EjbcaStartupValidator")
class EjbcaStartupValidatorTest {

    private AgentProperties properties;
    private EjbcaSigningService signingService;
    private EjbcaStartupValidator validator;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        AgentProperties.EjbcaProperties config = properties.getEjbca();
        config.setEnabled(true);
        config.setCredentialPath("kv://ejbca");
        config.setCaName("ManagementCA");
        config.setCertificateProfileName("ENDUSER");
        config.setEndEntityProfileName("EMPTY");

        signingService = mock(EjbcaSigningService.class);
        validator = new EjbcaStartupValidator(properties, signingService);
    }

    @Test
    @DisplayName("probes the CA when fully configured")
    void probesWhenConfigured() {
        when(signingService.probeVersion()).thenReturn("EJBCA 9.3.7 Community");

        validator.validate();

        verify(signingService).probeVersion();
    }

    @Test
    @DisplayName("does nothing when EJBCA is switched off")
    void skipsWhenDisabled() {
        properties.getEjbca().setEnabled(false);

        validator.validate();

        verify(signingService, never()).probeVersion();
    }

    @Test
    @DisplayName("does not waste a probe when required configuration is missing")
    void skipsProbeWhenConfigurationIncomplete() {
        properties.getEjbca().setCaName("  ");

        validator.validate();

        verify(signingService, never()).probeVersion();
    }

    @Test
    @DisplayName("probes when only credentials-json is set, without a credential-path")
    void probesWhenOnlyCredentialsJsonIsSet() {
        properties.getEjbca().setCredentialPath(null);
        properties.getEjbca().setCredentialsJson("{}");
        when(signingService.probeVersion()).thenReturn("EJBCA 9.3.7 Community");

        validator.validate();

        verify(signingService).probeVersion();
    }

    @Test
    @DisplayName("does not waste a probe when neither credential-path nor credentials-json is set")
    void skipsProbeWhenNoCredentialSource() {
        properties.getEjbca().setCredentialPath(null);

        validator.validate();

        verify(signingService, never()).probeVersion();
    }

    @Test
    @DisplayName("rejects a name source the resolver would refuse, before any traffic")
    void skipsProbeOnInvalidNameSource() {
        properties.getEjbca().setEndEntityNameSource("serialnumber");

        validator.validate();

        verify(signingService, never()).probeVersion();
    }

    @Test
    @DisplayName("accepts every name source the resolver supports")
    void acceptsValidNameSources() {
        when(signingService.probeVersion()).thenReturn("EJBCA 9.3.7 Community");
        properties.getEjbca().setEndEntityNameSource("DNS");

        validator.validate();

        verify(signingService).probeVersion();
    }

    @Test
    @DisplayName("a failed probe warns instead of aborting the boot")
    void probeFailureDoesNotBreakStartup() {
        when(signingService.probeVersion())
                .thenThrow(new PermanentAgentException("EJBCA_REST_DISABLED", "disabled"));

        // An agent with a broken EJBCA must still start and serve its other CAs.
        assertThatCode(() -> validator.validate()).doesNotThrowAnyException();
    }
}
