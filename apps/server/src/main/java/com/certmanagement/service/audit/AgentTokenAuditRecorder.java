// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditSubject;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Writes the audit rows for agent tokens: one created, one revoked. A row names the token by its id and
 * name only; the token value never reaches it. Each is written in the change's own transaction
 * ({@link AuditRecorder#record}, which requires one), so it commits and rolls back with the change.
 */
@Component
public class AgentTokenAuditRecorder {

    private final AuditRecorder recorder;

    public AgentTokenAuditRecorder(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    /** Token {@code tokenId} named {@code name} was created for the organization; {@code expiresAt} null = never. */
    public void tokenCreated(long organizationId, long tokenId, String name, OffsetDateTime expiresAt) {
        recorder.record(AuditEvents.success(AuditEventType.AGENT_TOKEN_CREATED, AuditSubject.builder()
                .organizationId(organizationId)
                .resourceId(tokenId)
                .resourceRef(Long.toString(tokenId))
                .name(name)
                .attributes(expiresAt == null ? Map.of() : Map.of("expiresAt", expiresAt.toString()))
                .build()));
    }

    /** Token {@code tokenId} named {@code name} of the organization was revoked. */
    public void tokenRevoked(long organizationId, long tokenId, String name) {
        recorder.record(AuditEvents.success(AuditEventType.AGENT_TOKEN_REVOKED, AuditSubject.builder()
                .organizationId(organizationId)
                .resourceId(tokenId)
                .resourceRef(Long.toString(tokenId))
                .name(name)
                .build()));
    }
}
