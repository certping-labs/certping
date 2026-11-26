// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Unified login payload. {@code identifier} is treated as an email if it contains '@',
 * otherwise as a username. The same endpoint serves every local-password account.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UnifiedLoginRequest {

    @NotBlank(message = "Identifier is required (email or username)")
    private String identifier;

    @NotBlank(message = "Password is required")
    private String password;
}
