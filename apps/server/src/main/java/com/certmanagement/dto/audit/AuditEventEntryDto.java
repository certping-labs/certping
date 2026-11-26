// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * One entry of the customer audit list: the fields the first audit page read, then the audit trail's own
 * fields. Built from an explicit field list: no trace id, job name or authentication method reaches a
 * customer.
 */
@Jacksonized
@Builder
@Schema(description = "Audit log entry: who did what to which resource, when, from where, and how it ended")
public record AuditEventEntryDto(
        @Schema(description = "Entry id", example = "9001") Long id,
        @Schema(description = "Member who acted; null for CertPing, anonymous or support entries", example = "42")
        Integer userId,
        @Schema(description = "Current email of the member who acted; null once they are removed", example = "alice@acme.com")
        String userEmail,
        @Schema(description = "Organization whose trail the entry belongs to", example = "7") Long organizationId,
        @Schema(description = "Current organization name, or \"Deleted organization\"", example = "Acme")
        String organizationName,
        @Schema(description = "Stable action code", example = "DELETE") String action,
        @Schema(description = "Resource type", example = "CREDENTIAL") String resource,
        @Schema(description = "Numeric id of the target, when it has one", example = "12") Long resourceId,
        @Schema(description = "Outcome", example = "SUCCESS", allowableValues = {"SUCCESS", "FAILURE", "PENDING"})
        String status,
        @Schema(description = "Details as a JSON object in a string: {\"attributes\":{...},\"changes\":[...]}",
                example = "{\"attributes\":{\"credentialType\":\"DNS\"}}")
        String details,
        @Schema(description = "Client address of the request", example = "203.0.113.7") String ipAddress,
        @Schema(description = "When it happened", example = "2026-10-07T09:30:00.123456Z") OffsetDateTime timestamp,

        // ── Audit trail fields ────────────────────────────────────────────
        @Schema(description = "Catalog event key", example = "credential.deleted") String event,
        @Schema(description = "What happened, as a sentence", example = "Deleted the Azure credential 'prod-dns'")
        String summary,
        @Schema(description = "Display name of the target", example = "prod-dns") String resourceName,
        @Schema(description = "Who acted", example = "USER", allowableValues = {"USER", "API_TOKEN", "SYSTEM", "ANONYMOUS"})
        String actorType,
        @Schema(description = "Who acted, as a name", example = "Alice Admin") String actorName,
        @Schema(description = "Failure reason code", example = "AZURE_PERMISSION_DENIED") String errorCode,
        @Schema(description = "Request id to quote to support", example = "0f8c2a9e") String requestId,
        @Schema(description = "Id of the flow or job attempt the entry belongs to", example = "corr-41")
        String correlationId,
        @Schema(description = "Fields changed, with before and after") List<AuditChangeDto> changes,

        // ── Descriptive fields ────────────────────────────────────────────
        @Schema(description = "Category key", example = "CREDENTIALS") String category,
        @Schema(description = "Stable string reference of the target (an xref)", example = "cred_8f2k")
        String resourceRef,
        @Schema(description = "Why it failed, in words a customer can act on",
                example = "CertPing doesn't have permission to do this in Azure.")
        String reason,
        @Schema(description = "Client user agent", example = "Mozilla/5.0") String userAgent,
        @Schema(description = "The event belongs to a feature that is now off for the organization", example = "false")
        boolean featureOff,
        @Schema(description = "Who asked for this system or agent action: their current name, \"a former member\", "
                + "or \"Platform administrator\"; null when nobody asked", example = "Alice Admin", nullable = true)
        String requestedByName) {

    /** One changed field. */
    @Schema(description = "A changed field")
    public record AuditChangeDto(
            @Schema(example = "name") String field,
            @Schema(example = "old-name") String before,
            @Schema(example = "new-name") String after) {
    }
}
