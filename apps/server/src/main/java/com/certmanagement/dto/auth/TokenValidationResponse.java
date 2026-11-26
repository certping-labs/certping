// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.util.List;

/**
 * Response DTO for token validation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Token validation result")
public class TokenValidationResponse {

    @Schema(description = "Whether the token is valid", example = "true")
    private boolean valid;

    @Schema(description = "Email from the token", example = "user@acme.com")
    private String email;

    @Schema(description = "User ID from the token", example = "42")
    private Integer userId;

    @Schema(description = "Organization ID from the token", example = "1")
    private Long organizationId;

    @Schema(description = "Roles from the token", example = "[\"ORGANIZATION_ADMIN\", \"CERT_MANAGER\"]")
    private List<String> roles;

    @Schema(description = "Permissions from the token", example = "[\"certificates.view\", \"certificates.manage\"]")
    private List<String> permissions;

    @Schema(description = "Error message if token is invalid", example = "Token has expired")
    private String error;
}
