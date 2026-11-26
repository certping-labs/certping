// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.OffsetDateTime;
import com.certmanagement.constants.ResourceType;
import com.certmanagement.constants.ActionType;
import com.certmanagement.constants.AuditStatus;

@Data
@Schema(description = "Filter criteria for querying audit logs")
public class AuditLogFilterRequest {

    @Schema(description = "Filter by organization ID (numeric identifier)", example = "1")
    private String organizationId;

    @Schema(description = "Filter by user ID", example = "42")
    private Integer userId;

        @Schema(description = "Filter by resource type (e.g. CERTIFICATE, USER, ORGANIZATION, SSO_CONFIG)", example = "CERTIFICATE")
        private ResourceType resourceType;

    @Schema(description = "Filter by action (e.g. API_READ, API_CREATE, API_UPDATE, API_DELETE, SSO_LOGIN)",
            example = "API_CREATE")
        private ActionType action;

    @Schema(description = "Filter by status (SUCCESS or FAILURE)", example = "SUCCESS")
        private AuditStatus status;

    @Schema(description = "Start of date range (ISO 8601)", example = "2026-01-01T00:00:00")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime from;

    @Schema(description = "End of date range (ISO 8601)", example = "2026-01-31T23:59:59")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime to;
}
