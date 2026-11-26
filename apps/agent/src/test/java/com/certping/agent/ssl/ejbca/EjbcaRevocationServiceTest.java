// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EjbcaRevocationServiceTest {
    private final EjbcaClient client = mock(EjbcaClient.class);
    private final EjbcaRevocationService service = new EjbcaRevocationService(client);
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @BeforeEach
    void setUp() throws Exception {
        when(client.revocationStatus("CN=Issuer", "abc"))
                .thenReturn(status(false, "NOT_REVOKED"),
                        objectMapper.readTree("""
                                {"issuer_dn":"CN=Issuer","serial_number":"0ABC",
                                 "revoked":true,"revocation_reason":"KEY_COMPROMISE",
                                 "revocation_date":"2026-09-01T00:00:00Z"}
                                """));
    }

    @Test
    void revokesThenRequiresSynchronousConfirmation() {
        EjbcaRevocationService.Result result = service.revoke(
                "CN=Issuer", "abc", "KEY_COMPROMISE");

        verify(client).revoke("CN=Issuer", "abc", "KEY_COMPROMISE");
        assertThat(result.alreadyRevoked()).isFalse();
        assertThat(result.reason()).isEqualTo("KEY_COMPROMISE");
    }

    @Test
    void alreadyRevokedIsAnIdempotentSuccess() throws Exception {
        when(client.revocationStatus("CN=Issuer", "abc"))
                .thenReturn(status(true, "SUPERSEDED"));

        EjbcaRevocationService.Result result = service.revoke(
                "CN=Issuer", "abc", "KEY_COMPROMISE");

        assertThat(result.alreadyRevoked()).isTrue();
        verify(client, never()).revoke("CN=Issuer", "abc", "KEY_COMPROMISE");
    }

    @Test
    void rejectsUnsafeReasonBeforeCallingEjbca() {
        assertThatThrownBy(() -> service.revoke("CN=Issuer", "abc", "CA_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("Unsupported EJBCA leaf-certificate revocation reason");
    }

    @Test
    void confirmsWhenConcurrentDuplicateRevokeReturnsConflict() throws Exception {
        when(client.revocationStatus("CN=Issuer", "abc"))
                .thenReturn(status(false, "NOT_REVOKED"), status(true, "KEY_COMPROMISE"));
        org.mockito.Mockito.doThrow(new PermanentAgentException(
                        "EJBCA_API_ERROR", "already revoked"))
                .when(client).revoke("CN=Issuer", "abc", "KEY_COMPROMISE");

        EjbcaRevocationService.Result result = service.revoke(
                "CN=Issuer", "abc", "KEY_COMPROMISE");

        assertThat(result.alreadyRevoked()).isTrue();
        assertThat(result.reason()).isEqualTo("KEY_COMPROMISE");
    }

    @Test
    void rejectsMissingRevokedField() throws Exception {
        when(client.revocationStatus("CN=Issuer", "abc"))
                .thenReturn(objectMapper.readTree("""
                        {"issuer_dn":"CN=Issuer","serial_number":"abc"}
                        """));

        assertThatThrownBy(() -> service.status("CN=Issuer", "abc"))
                .isInstanceOf(TransientAgentException.class)
                .hasMessageContaining("boolean revoked");
    }

    @Test
    void rejectsMismatchedCertificateIdentity() throws Exception {
        when(client.revocationStatus("CN=Issuer", "abc"))
                .thenReturn(objectMapper.readTree("""
                        {"issuer_dn":"CN=Other","serial_number":"abc","revoked":false}
                        """));

        assertThatThrownBy(() -> service.status("CN=Issuer", "abc"))
                .isInstanceOf(TransientAgentException.class)
                .hasMessageContaining("different certificate");
    }

    @Test
    void acceptsCanonicalIssuerAndSerialRepresentations() throws Exception {
        when(client.revocationStatus("CN=Issuer,O=Example", "00:AB:C"))
                .thenReturn(objectMapper.readTree("""
                        {"issuer_dn":"cn=Issuer,o=Example","serial_number":"abc","revoked":false}
                        """));

        assertThat(service.status("CN=Issuer,O=Example", "00:AB:C").revoked()).isFalse();
    }

    @Test
    void acceptedWriteWithoutConfirmationIsRetryable() throws Exception {
        when(client.revocationStatus("CN=Issuer", "abc"))
                .thenReturn(status(false, null), status(false, null));

        assertThatThrownBy(() -> service.revoke(
                "CN=Issuer", "abc", "CESSATION_OF_OPERATION"))
                .isInstanceOf(TransientAgentException.class)
                .hasMessageContaining("still reports");
    }

    private JsonNode status(boolean revoked, String reason) throws Exception {
        return objectMapper.readTree("""
                {"issuer_dn":"CN=Issuer","serial_number":"abc",
                 "revoked":%s,"revocation_reason":"%s"}
                """.formatted(revoked, reason));
    }
}
