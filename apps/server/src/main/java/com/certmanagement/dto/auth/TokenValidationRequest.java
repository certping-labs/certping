// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

/**
 * Request DTO for validating a token.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request to validate a JWT token")
public class TokenValidationRequest {

    @NotBlank(message = "Token is required")
    @Schema(description = "The JWT token to validate", 
            example = "eyJhbGciOiJIUzUxMiJ9...", 
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String token;
}
