// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import lombok.*;

import java.util.Set;

/**
 * Request DTO for updating a user.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request to update a user")
public class UpdateUserRequest {

    @Email(message = "Invalid email format")
    @Schema(description = "Updated email address", example = "newemail@acme.com")
    private String email;

    @Schema(description = "Updated IDP User ID", example = "okta-user-new-123")
    private String idpUserId;

    @Schema(description = "Role names to assign to the user", example = "[\"ORGANIZATION_ADMIN\", \"CERT_MANAGER\"]")
    private Set<String> roles;

    @Schema(description = "Whether the user account is enabled", example = "true")
    private Boolean enabled;
}
