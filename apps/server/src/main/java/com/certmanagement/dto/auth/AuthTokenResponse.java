// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.util.Set;

/**
 * Response DTO for authentication containing JWT tokens and user info.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Authentication response containing JWT tokens and user information")
public class AuthTokenResponse {

    @Schema(description = "JWT access token", example = "eyJhbGciOiJIUzUxMiJ9...")
    private String accessToken;

    @Schema(description = "JWT refresh token for obtaining new access tokens", example = "eyJhbGciOiJIUzUxMiJ9...")
    private String refreshToken;

    @Schema(description = "Token type", example = "Bearer")
    private String tokenType;

    @Schema(description = "Token expiration time in seconds", example = "3600")
    private Long expiresIn;
    
    // User info
    @Schema(description = "User ID", example = "42")
    private Integer userId;

    @Schema(description = "User email address", example = "admin@acme.com")
    private String email;

    @Schema(description = "User display name", example = "John Doe")
    private String displayName;

    @Schema(description = "Organization ID the user belongs to", example = "1")
    private Long organizationId;

    @Schema(description = "Organization name", example = "ACME Corporation")
    private String organizationName;

    @Schema(description = "User roles", example = "[\"ADMIN\", \"CERT_MANAGER\"]")
    private Set<String> roles;

    @Schema(description = "User permissions", example = "[\"certificates.view\", \"certificates.manage\"]")
    private Set<String> permissions;
}
