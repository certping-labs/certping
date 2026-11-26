// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.scep.CaUnavailableException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.smallstep.SmallstepRevocationService;
import com.certping.agent.ssl.smallstep.SmallstepSigningService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SmallstepScepCaBackendTest {
    private SmallstepSigningService signingService;
    private SmallstepRevocationService revocationService;
    private SmallstepScepCaBackend backend;

    @BeforeEach
    void setUp() {
        signingService = mock(SmallstepSigningService.class);
        revocationService = mock(SmallstepRevocationService.class);
        backend = new SmallstepScepCaBackend(signingService, revocationService,
                mock(SecretStore.class), new AgentProperties(), JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void transientRenewalStatusFailureRemainsRetryable() {
        X509Certificate certificate = mock(X509Certificate.class);
        doThrow(new TransientAgentException("SMALLSTEP_NETWORK_ERROR", "offline"))
                .when(revocationService).assertRenewalAllowed(certificate);

        assertThatThrownBy(() -> backend.assertRenewalAllowed(certificate))
                .isInstanceOf(CaUnavailableException.class)
                .hasMessage("offline");
    }

    @Test
    void definiteRevocationRejectionRemainsATerminalCaFailure() {
        X509Certificate certificate = mock(X509Certificate.class);
        doThrow(new PermanentAgentException(
                        "SMALLSTEP_CERTIFICATE_REVOKED", "certificate revoked"))
                .when(revocationService).assertRenewalAllowed(certificate);

        assertThatThrownBy(() -> backend.assertRenewalAllowed(certificate))
                .isInstanceOf(CaException.class)
                .hasMessage("certificate revoked");
    }

    @Test
    void transientSigningFailureRemainsRetryable() {
        PKCS10CertificationRequest csr = mock(PKCS10CertificationRequest.class);
        when(signingService.sign(csr, null)).thenThrow(
                new TransientAgentException("SMALLSTEP_NETWORK_ERROR", "offline"));

        assertThatThrownBy(() -> backend.sign(csr, null))
                .isInstanceOf(CaUnavailableException.class)
                .hasMessage("offline");
    }
}
