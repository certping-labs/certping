// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

import java.time.OffsetDateTime;

/**
 * One read in the Access view ({@code GET /api/v1/audit-logs/access}): what was read, by whom, from where,
 * and whether it was answered. The fields the web app's Access components read come first, then the
 * descriptive ones. A read a platform super admin made in another organization is shown there as "CertPing
 * support", with nothing of who made it or from where.
 */
@Jacksonized
@Builder
@Schema(description = "A read of something sensitive: who read what, when, from where")
public record AuditAccessEntryDto(
        // ── The Access components' fields ─────────────────────────────────
        @Schema(description = "Entry id", example = "9101") Long id,
        @Schema(description = "When it happened", example = "2026-10-07T09:30:00.123456Z") OffsetDateTime timestamp,
        @Schema(description = "The kind of read, from /access/activities", example = "access.agent_connection_viewed")
        String activity,
        @Schema(description = "What was read: its name, else its reference", example = "cred_8f2k", nullable = true)
        String target,
        @Schema(description = "Numeric id of what was read, when it has one", example = "12", nullable = true)
        Long resourceId,
        @Schema(description = "Outcome", example = "SUCCESS") String status,
        @Schema(description = "Failure reason code", example = "RATE_LIMITED", nullable = true) String errorCode,
        @Schema(description = "Who read: a member's name, or \"Platform administrator\"", example = "Alice Admin")
        String actor,
        @Schema(description = "Member who read; null for platform administrators", example = "42", nullable = true)
        Integer userId,
        @Schema(description = "Current email of the member who read", example = "alice@acme.com", nullable = true)
        String userEmail,
        @Schema(description = "Client address", example = "203.0.113.7", nullable = true) String ipAddress,
        @Schema(description = "Request id to quote to support", example = "0f8c2a9e", nullable = true) String requestId,
        @Schema(description = "Correlation id", example = "corr-41", nullable = true) String correlationId,

        // ── Descriptive fields ────────────────────────────────────────────
        @Schema(description = "What happened, as a sentence", example = "Viewed the agent's connection string")
        String summary,
        @Schema(description = "Why it failed, in words a customer can act on", nullable = true) String reason,
        @Schema(description = "Client user agent", example = "Mozilla/5.0", nullable = true) String userAgent,
        @Schema(description = "Organization whose trail the entry belongs to", example = "7") Long organizationId) {
}
