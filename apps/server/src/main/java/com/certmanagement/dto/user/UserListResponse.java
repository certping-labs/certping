// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.util.List;

/**
 * Response DTO for listing users.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response containing a list of users")
public class UserListResponse {

    @Schema(description = "List of users")
    private List<UserDto> users;

    @Schema(description = "Total number of users", example = "25")
    private int count;
}
