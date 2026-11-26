// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Request DTO for creating a new local user.
 * Distinct from dto/user/CreateUserRequest (which is for SSO user provisioning).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserRequest {

    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 12, message = "Password must be at least 12 characters")
    private String password;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    private String displayName;

    /**
     * Role IDs to assign to the user.
     * Permissions are derived from assigned roles.
     */
    private Set<Long> roleIds;

    /**
     * Target organization for user creation.
     * Required when caller is SUPER_ADMIN; ignored for organization-scoped callers unless used for consistency checks.
     */
    private Long organizationId;
}
