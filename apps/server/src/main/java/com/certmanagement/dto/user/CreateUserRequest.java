// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.Set;

/**
 * Request DTO for creating a user.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request to create a new user")
public class CreateUserRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(description = "Email address of the user", example = "newuser@acme.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @NotNull(message = "Organization ID is required")
    @Schema(description = "ID of the organization the user belongs to", example = "1", requiredMode = Schema.RequiredMode.REQUIRED)
    private Long organizationId;

    @Schema(description = "User ID from the identity provider", example = "okta-user-123")
    private String idpUserId;

    @Schema(description = "Role names to assign to the user", example = "[\"VIEWER\"]")
    private Set<String> roles;

    @Schema(description = "Whether the user account is enabled", example = "true", defaultValue = "true")
    @Builder.Default
    private Boolean enabled = true;
}
