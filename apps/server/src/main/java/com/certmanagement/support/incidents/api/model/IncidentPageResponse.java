// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(description = "Paginated incident history")
public record IncidentPageResponse(
        @Schema(description = "Zero-based page index", example = "0")
        int page,
        @Schema(description = "Requested page size", example = "50")
        int size,
        @Schema(description = "Total number of stored incidents", example = "12")
        long totalElements,
        @Schema(description = "Total number of available pages", example = "1")
        int totalPages,
        @Schema(description = "Current page content")
        List<IncidentResponse> items
) {
}
