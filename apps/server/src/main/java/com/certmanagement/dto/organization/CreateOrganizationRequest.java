// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.organization;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;

/**
 * Request DTO for creating a new organization.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request to create a new organization")
public class CreateOrganizationRequest {

    @NotBlank(message = "Name is required")
    @Schema(description = "Name of the organization", example = "ACME Corporation", requiredMode = Schema.RequiredMode.REQUIRED)
    private String name;

    @NotBlank(message = "Domain is required")
    @Pattern(regexp = "^[a-zA-Z0-9][a-zA-Z0-9-]*\\.[a-zA-Z]{2,}$", message = "Invalid domain format")
    @Schema(description = "Domain of the organization (e.g., acme.com)", example = "acme.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String domain;

    @Schema(description = "Whether the organization is active", example = "true", defaultValue = "true")
    @Builder.Default
    private Boolean active = true;
}