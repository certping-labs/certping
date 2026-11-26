// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

/**
 * Request DTO for deleting a user (placeholder for future extensibility).
 */
@Data
@Builder
@NoArgsConstructor
@Schema(description = "Request to delete a user (empty, for future extensibility)")
public class DeleteUserRequest {
    // No fields required for now
}
