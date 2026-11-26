// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.util.List;

/**
 * Response DTO for current user information.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Current authenticated user information")
public class CurrentUserResponse {

    @Schema(description = "User ID", example = "42")
    private Integer userId;

    @Schema(description = "Email address", example = "user@acme.com")
    private String email;

    @Schema(description = "Display name", example = "John Doe")
    private String displayName;

    @Schema(description = "Organization ID", example = "1")
    private Long organizationId;

    @Schema(description = "Organization name", example = "ACME Corporation")
    private String organizationName;

    @Schema(description = "User roles", example = "[\"ORGANIZATION_ADMIN\", \"CERT_MANAGER\"]")
    private List<String> roles;

    @Schema(description = "User permissions", example = "[\"certificates.view\", \"certificates.manage\"]")
    private List<String> permissions;

    @Schema(description = "Authentication method used", example = "OIDC",
            allowableValues = {"OIDC", "PASSWORD", "SSO"})
    private String authMethod;
}
