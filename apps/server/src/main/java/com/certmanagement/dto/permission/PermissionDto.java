// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.permission;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "System permission")
public class PermissionDto {

    @Schema(description = "Permission ID", example = "1")
    private Long id;

    @Schema(description = "Permission name (resource:action)", example = "certificates:view")
    private String name;

    @Schema(description = "Resource category", example = "certificates")
    private String resource;

    @Schema(description = "Action type", example = "view")
    private String action;

    @Schema(description = "Human-readable description", example = "View certificates")
    private String description;

    @Schema(description = "Feature flag this permission belongs to, or null for a core permission. "
            + "Permissions of a feature that is off for the organization are left out of responses.",
            example = "IOT_DEVICE_MANAGEMENT", nullable = true)
    private String featureKey;
}
