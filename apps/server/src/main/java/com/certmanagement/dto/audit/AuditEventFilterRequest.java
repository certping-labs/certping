// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.OffsetDateTime;

/**
 * The filters of {@code GET /api/v1/audit-logs}. Every one is optional. Values are validated when the
 * query is built ({@link com.certmanagement.audit.AuditTrailReader}); a malformed one is a 400.
 */
@Data
@Schema(description = "Filters of the audit log list")
public class AuditEventFilterRequest {

    @Schema(description = "Super admins only: the organization whose trail to read; omitted reads every "
            + "organization. Others may pass only their own.", example = "7")
    private String organizationId;

    @Schema(description = "Member who acted", example = "42")
    private Integer userId;

    @Schema(description = "Who acted: USER, SYSTEM (CertPing itself), ANONYMOUS or API_TOKEN", example = "SYSTEM")
    private String actorType;

    @Schema(description = "Action code from /actions", example = "DELETE")
    private String action;

    @Schema(description = "Catalog event key", example = "credential.deleted")
    private String event;

    @Schema(description = "Category key from /categories", example = "CREDENTIALS")
    private String category;

    @Schema(description = "Resource type from /resources", example = "CREDENTIAL")
    private String resourceType;

    @Schema(description = "Numeric id of the target", example = "12")
    private Long resourceId;

    @Schema(description = "Stable string reference of the target (an xref)", example = "cred_8f2k")
    private String resourceRef;

    @Schema(description = "Display name of the target, matched whole and ignoring case", example = "prod-dns")
    private String resourceName;

    @Schema(description = "Outcome: SUCCESS, FAILURE or PENDING (legacy name of outcome)", example = "FAILURE")
    private String status;

    @Schema(description = "Outcome: SUCCESS, FAILURE or PENDING", example = "FAILURE")
    private String outcome;

    @Schema(description = "Request id, as quoted to support", example = "0f8c2a9e")
    private String requestId;

    @Schema(description = "Correlation id of a flow or job attempt", example = "corr-41")
    private String correlationId;

    @Schema(description = "Start of the range (ISO 8601). Clamped to visibleFrom for customers.",
            example = "2026-09-01T00:00:00Z")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime from;

    @Schema(description = "End of the range, inclusive (ISO 8601)", example = "2026-09-30T23:59:59Z")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime to;

    @Schema(description = "nextCursor of the previous page. Cannot be combined with page.")
    private String cursor;
}
