// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.role;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Role with associated permissions")
public class RoleDto {

    @Schema(description = "Role ID", example = "1")
    private Long id;

    @Schema(description = "Role name", example = "CERT_MANAGER")
    private String name;

    @Schema(description = "Role description", example = "Manage certificates")
    private String description;

    @Schema(description = "Organization ID (null for system roles)")
    private Long organizationId;

    @Schema(description = "Whether this is a system-defined role", example = "true")
    private Boolean isSystemRole;

    @Schema(description = "Permission names assigned to this role")
    private Set<String> permissions;

    @Schema(description = "Created timestamp")
    private OffsetDateTime createdAt;

    @Schema(description = "Updated timestamp")
    private OffsetDateTime updatedAt;
}
