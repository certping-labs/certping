// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.common;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

/**
 * Generic message response DTO.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Generic message response")
public class MessageResponse {

    @Schema(description = "Response message", example = "Operation completed successfully")
    private String message;

    @Schema(description = "Whether the operation was successful", example = "true")
    @Builder.Default
    private boolean success = true;
}
