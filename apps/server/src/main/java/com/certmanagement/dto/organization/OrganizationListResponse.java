// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.organization;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.util.List;

/**
 * Response DTO for listing organizations.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response containing a list of organizations")
public class OrganizationListResponse {

    @Schema(description = "List of organizations")
    private List<OrganizationDto> organizations;

    @Schema(description = "Total number of organizations", example = "5")
    private int count;
}