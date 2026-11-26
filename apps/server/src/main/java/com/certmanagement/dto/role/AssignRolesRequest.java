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
@Schema(description = "Assign roles to a user")
public class AssignRolesRequest {

    @NotNull(message = "Role IDs are required")
    @Schema(description = "Set of role IDs to assign to the user. This replaces all existing role assignments.",
            example = "[1, 2, 5]",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private Set<Long> roleIds;
}
