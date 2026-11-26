// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

/**
 * Request DTO for disabling a user (placeholder for future extensibility).
 */
@Data
@Builder
@NoArgsConstructor
@Schema(description = "Request to disable a user (empty, for future extensibility)")
public class DisableUserRequest {
    // No fields required for now
}
