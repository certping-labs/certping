// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.util.Set;

/**
 * DTO for user data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "User account information")
public class UserDto {

    @Schema(description = "Unique identifier of the user", example = "42", accessMode = Schema.AccessMode.READ_ONLY)
    private Integer id;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(description = "Email address of the user", example = "admin@acme.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @Schema(description = "ID of the organization the user belongs to", example = "1")
    private Long organizationId;

    @Schema(description = "Name of the organization the user belongs to", example = "ACME Corporation", accessMode = Schema.AccessMode.READ_ONLY)
    private String organizationName;

    @Schema(description = "User ID from the identity provider", example = "okta-user-123")
    private String idpUserId;

    @Schema(description = "Username for local auth users", example = "jdoe")
    private String username;

    @Schema(description = "Display name", example = "Jane Doe")
    private String displayName;

    @Schema(description = "Authentication method (LOCAL or SSO)", example = "SSO")
    private String authMethod;

    @Schema(description = "Whether the user must change their password on next login", example = "false")
    private Boolean mustChangePassword;

    @Schema(description = "Roles assigned to the user", example = "[\"ADMIN\", \"USER\"]")
    private Set<String> roles;

    @Schema(description = "Permissions granted to the user", example = "[\"certificates.view\", \"certificates.manage\"]", accessMode = Schema.AccessMode.READ_ONLY)
    private Set<String> permissions;

    @Schema(description = "Whether the user account is active", example = "true")
    private Boolean active;

    @Schema(description = "Whether the user account is enabled", example = "true")
    private boolean enabled;
}
