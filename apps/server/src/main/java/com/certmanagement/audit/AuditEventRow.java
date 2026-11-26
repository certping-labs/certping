// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;
import java.util.Objects;

/**
 * One {@code audit_events} row as it is written. Build it with {@link AuditEvents}, which fills the
 * actor and origin from the current {@link AuditContext}; the store sanitises it
 * ({@link AuditSanitizer}) before it reaches the database.
 *
 * @param organizationId   the trail the row belongs to; {@code null} for platform-wide rows. Only the id
 *                         is stored: see {@link AuditDisplayNames#organization} for how it is read
 * @param actorLabel       filled by the store from the user (name, else email) when left empty
 * @param actorStaff       a super admin acting in another organization's trail
 * @param errorCode        an {@link AuditReason} code on failure rows
 */
@Jacksonized
@Builder(toBuilder = true)
public record AuditEventRow(
        Instant occurredAt,
        AuditVisibility visibility,
        String event,
        String category,
        String featureKey,
        Long organizationId,
        AuditActorType actorType,
        Integer actorUserId,
        String actorLabel,
        String actorJob,
        boolean actorStaff,
        String authMethod,
        String action,
        String resourceType,
        Long resourceId,
        String resourceRef,
        String resourceName,
        AuditOutcome outcome,
        String errorCode,
        String summary,
        AuditDetails details,
        String ipAddress,
        String userAgent,
        String requestId,
        String correlationId,
        String traceId) {

    public AuditEventRow {
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(visibility, "visibility");
        Objects.requireNonNull(actorType, "actorType");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(resourceType, "resourceType");
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(summary, "summary");
        if (visibility == AuditVisibility.CUSTOMER && (event == null || category == null)) {
            throw new IllegalArgumentException("a customer row needs an event and a category");
        }
        details = details == null ? AuditDetails.NONE : details;
    }
}
