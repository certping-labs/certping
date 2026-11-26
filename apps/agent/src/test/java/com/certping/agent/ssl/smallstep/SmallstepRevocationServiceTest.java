// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SmallstepRevocationServiceTest {
    @Mock private SmallstepClient client;
    @Mock private X509Certificate certificate;
    private AgentProperties properties;
    private SmallstepRevocationService service;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getSmallstep().setEnabled(true);
        service = new SmallstepRevocationService(client, properties);
    }

    @Test
    void revokeDelegatesToTheVerifiedClientFlow() {
        SmallstepRevocationService.Result expected = new SmallstepRevocationService.Result(
                false, "KEY_COMPROMISE", "2026-09-01T00:00:00Z");
        when(client.revoke("CN=Issuer", "abc", "KEY_COMPROMISE")).thenReturn(expected);

        assertThat(service.revoke("CN=Issuer", "abc", "KEY_COMPROMISE"))
                .isSameAs(expected);
    }

    @Test
    void revokedRenewalCertificateFailsClosed() {
        when(certificate.getIssuerX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Issuer"));
        when(certificate.getSerialNumber()).thenReturn(BigInteger.valueOf(0xabc));
        when(client.isRevoked("CN=Issuer", "abc")).thenReturn(true);

        assertThatThrownBy(() -> service.assertRenewalAllowed(certificate))
                .isInstanceOfSatisfying(PermanentAgentException.class, exception ->
                        assertThat(exception.getErrorCode())
                                .isEqualTo("SMALLSTEP_CERTIFICATE_REVOKED"));
    }

    @Test
    void disabledConnectorRejectsRevocationBeforeAnyCaCall() {
        properties.getSmallstep().setEnabled(false);

        assertThatThrownBy(() -> service.revoke("CN=Issuer", "abc", "KEY_COMPROMISE"))
                .isInstanceOfSatisfying(PermanentAgentException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo("SMALLSTEP_DISABLED"));
        verify(client, org.mockito.Mockito.never())
                .revoke(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any());
    }
}
