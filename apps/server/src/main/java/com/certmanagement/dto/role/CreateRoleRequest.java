// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.role;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Create a new custom role")
public class CreateRoleRequest {

    @NotBlank(message = "Role name is required")
    @Schema(description = "Role name", example = "SECURITY_AUDITOR", requiredMode = Schema.RequiredMode.REQUIRED)
    private String name;

    @Schema(description = "Role description", example = "Security auditing access")
    private String description;

    @Schema(description = "Permission names to assign to this role",
            example = "[\"certificates:view\", \"audit:view\"]")
    private Set<String> permissionNames;
}
