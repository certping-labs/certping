// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

import java.time.Instant;

/**
 * One {@code audit_events} row as the read path loads it. A customer view renders only what a customer may
 * see ({@link AuditEntryRenderer} builds its entries from an explicit field list); the platform view adds the
 * staff fields at the end (visibility, job, authentication method, trace id). Names are rendered from it at
 * read time ({@link AuditDisplayNames}).
 *
 * @param details    the stored {@code details} JSON object, as text, or {@code null}
 * @param visibility {@code CUSTOMER} or {@code INTERNAL}; platform view only
 * @param actorJob   the job a system actor ran; platform view only
 * @param authMethod how the actor signed in; platform view only
 * @param traceId    the OpenTelemetry trace; platform view only
 */
@Jacksonized
@Builder(toBuilder = true)
public record AuditEventRecord(
        long id,
        Instant occurredAt,
        String event,
        String category,
        String featureKey,
        Long organizationId,
        String actorType,
        Integer actorUserId,
        String actorLabel,
        boolean actorStaff,
        String action,
        String resourceType,
        Long resourceId,
        String resourceRef,
        String resourceName,
        String outcome,
        String errorCode,
        String summary,
        String details,
        String ipAddress,
        String userAgent,
        String requestId,
        String correlationId,
        String visibility,
        String actorJob,
        String authMethod,
        String traceId) {
}
