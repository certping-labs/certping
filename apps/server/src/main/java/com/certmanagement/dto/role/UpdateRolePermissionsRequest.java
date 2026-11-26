// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.role;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Update permissions for a role")
public class UpdateRolePermissionsRequest {

    @NotNull(message = "Permission names are required")
    @Schema(description = "Complete set of permission names to assign to the role. This replaces all existing permissions.",
            example = "[\"certificates:view\", \"certificates:create\", \"audit:view\"]",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private Set<String> permissionNames;
}
