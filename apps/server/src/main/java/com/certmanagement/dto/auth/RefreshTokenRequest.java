// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

/**
 * Request DTO for refreshing an access token.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request to refresh an access token using a refresh token")
public class RefreshTokenRequest {

    @NotBlank(message = "Refresh token is required")
    @Schema(description = "The refresh token obtained during login", 
            example = "eyJhbGciOiJIUzUxMiJ9...", 
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String refreshToken;
}
