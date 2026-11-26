// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.OffsetDateTime;

/**
 * The filters of the Access view ({@code GET /api/v1/audit-logs/access} and its export): {@code activity},
 * {@code userId}, {@code resourceName}, {@code status} and the range, plus the list's ids. Every one is
 * optional.
 */
@Data
@Schema(description = "Filters of the Access view")
public class AuditAccessFilterRequest {

    @Schema(description = "Super admins only: the organization whose reads to list. Others may pass only their own.",
            example = "7")
    private String organizationId;

    @Schema(description = "The kind of read, from /access/activities", example = "access.agent_connection_viewed")
    private String activity;

    @Schema(description = "Member who read", example = "42")
    private Integer userId;

    @Schema(description = "Name of what was read, matched whole and ignoring case", example = "prod-dns")
    private String resourceName;

    @Schema(description = "Stable reference of what was read", example = "cred_8f2k")
    private String resourceRef;

    @Schema(description = "Outcome: SUCCESS or FAILURE", example = "SUCCESS")
    private String status;

    @Schema(description = "Request id, as quoted to support", example = "0f8c2a9e")
    private String requestId;

    @Schema(description = "Correlation id", example = "corr-41")
    private String correlationId;

    @Schema(description = "Start of the range (ISO 8601). Clamped to visibleFrom.", example = "2026-09-01T00:00:00Z")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime from;

    @Schema(description = "End of the range, inclusive (ISO 8601)", example = "2026-09-30T23:59:59Z")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime to;

    @Schema(description = "nextCursor of the previous page")
    private String cursor;

    /** The list's filters these stand for: the kind of read is the event. */
    public AuditEventFilterRequest toEventFilter() {
        AuditEventFilterRequest filter = new AuditEventFilterRequest();
        filter.setOrganizationId(organizationId);
        filter.setEvent(activity);
        filter.setUserId(userId);
        filter.setResourceName(resourceName);
        filter.setResourceRef(resourceRef);
        filter.setStatus(status);
        filter.setRequestId(requestId);
        filter.setCorrelationId(correlationId);
        filter.setFrom(from);
        filter.setTo(to);
        filter.setCursor(cursor);
        return filter;
    }
}
