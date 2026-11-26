// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import com.certmanagement.messaging.transport.AgentTokenService.AgentToken;
import com.certmanagement.service.audit.AgentTokenAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Creating and revoking an agent token writes an audit row that names the token, never its value. */
@ExtendWith(MockitoExtension.class)
class AgentTokenServiceAuditTest {

    @Mock
    private JdbcTemplate jdbc;

    @Mock
    private AgentTokenAuditRecorder auditRecorder;

    private AgentTokenService service;

    @BeforeEach
    void setUp() {
        service = new AgentTokenService(jdbc, new TransportProperties());
        service.setAuditRecorder(auditRecorder);
    }

    @Test
    void createRecordsTheTokensIdAndName() {
        OffsetDateTime expires = OffsetDateTime.parse("2027-01-01T00:00:00Z");
        AgentToken row = new AgentToken(5L, 7L, "edge", "cpa_abcdef", "admin", OffsetDateTime.now(), null, null,
                expires);
        when(jdbc.queryForObject(anyString(), ArgumentMatchers.<RowMapper<AgentToken>>any(),
                any(), any(), any(), any(), any(), any())).thenReturn(row);

        AgentTokenService.CreatedToken created = service.create(7L, "edge", "admin", expires);

        assertThat(created.plainToken()).startsWith(AgentTokenService.TOKEN_PREFIX);
        verify(auditRecorder).tokenCreated(7L, 5L, "edge", expires);
    }

    @Test
    void revokeRecordsTheRevokedToken() {
        when(jdbc.queryForList(anyString(), eq(String.class), eq(5L), eq(7L))).thenReturn(List.of("edge"));

        assertThat(service.revoke(7L, 5L)).isTrue();

        verify(auditRecorder).tokenRevoked(7L, 5L, "edge");
    }

    @Test
    void revokingAnotherOrganizationsOrAnAlreadyRevokedTokenRecordsNothing() {
        when(jdbc.queryForList(anyString(), eq(String.class), eq(5L), eq(8L))).thenReturn(List.of());

        assertThat(service.revoke(8L, 5L)).isFalse();

        verifyNoInteractions(auditRecorder);
    }
}
