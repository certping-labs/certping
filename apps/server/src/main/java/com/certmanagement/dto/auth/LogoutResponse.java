// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

/**
 * Response DTO for logout operation.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Logout response")
public class LogoutResponse {

    @Schema(description = "Logout message", example = "Logged out successfully")
    private String message;

    @Schema(description = "Whether logout was successful", example = "true")
    @Builder.Default
    private boolean success = true;
}
