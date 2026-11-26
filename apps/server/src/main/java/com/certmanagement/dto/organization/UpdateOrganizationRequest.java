// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.organization;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Pattern;
import lombok.*;

/**
 * Request DTO for updating an organization. The agent heartbeat cadence is not set here: it has its
 * own endpoint, which bounds it and checks the AGENT_HEALTH_MONITORING flag.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request to update a organization")
public class UpdateOrganizationRequest {

    @Schema(description = "Updated name of the organization", example = "ACME Corporation Updated")
    private String name;

    @Pattern(regexp = "^[a-zA-Z0-9][a-zA-Z0-9-]*\\.[a-zA-Z]{2,}$", message = "Invalid domain format")
    @Schema(description = "Updated domain of the organization", example = "acme-new.com")
    private String domain;

    @Schema(description = "Whether the organization is active", example = "true")
    private Boolean active;
}