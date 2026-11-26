// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.organization;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.time.OffsetDateTime;

/**
 * DTO for organization data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Organization organization data")
public class OrganizationDto {

    @Schema(description = "Unique identifier of the organization", example = "1", accessMode = Schema.AccessMode.READ_ONLY)
    private Long id;

    @NotBlank(message = "Name is required")
    @Schema(description = "Name of the organization", example = "ACME Corporation", requiredMode = Schema.RequiredMode.REQUIRED)
    private String name;

    @NotBlank(message = "Domain is required")
    @Schema(description = "Domain of the organization", example = "acme.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String domain;

    @Schema(description = "Unique URL-friendly slug of the organization", example = "acme-corporation", accessMode = Schema.AccessMode.READ_ONLY)
    private String slug;

    @Schema(description = "Whether the organization is active", example = "true", defaultValue = "true")
    private Boolean active;

    @Schema(description = "Organization type; every organization is B2B", example = "B2B", allowableValues = {"B2B"})
    private String orgType;

    @Min(1)
    @Max(60)
    @Schema(description = "Heartbeat cadence in minutes, 1 to 60", example = "5")
    private Integer agentHeartbeatCadenceMinutes;

    @Schema(description = "Timestamp when the organization was created", example = "2024-01-15T10:30:00", accessMode = Schema.AccessMode.READ_ONLY)
    private OffsetDateTime createdAt;

    @Schema(description = "Timestamp when the organization was last updated", example = "2024-01-20T14:45:00", accessMode = Schema.AccessMode.READ_ONLY)
    private OffsetDateTime updatedAt;

    @Schema(description = "Custom soft-delete retention period in days for this organization. Overrides the global setting when set.", example = "60")
    private Integer softDeleteRetentionDays;
}