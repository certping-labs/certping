// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import io.swagger.v3.oas.annotations.media.Schema;

public record CreatePagerDutyIncidentResponse(
        @Schema(description = "PagerDuty enqueue status.", example = "success")
        String status,
        @Schema(description = "PagerDuty response message.", example = "Event processed")
        String message,
        @Schema(description = "PagerDuty deduplication key associated with the created or updated alert.", example = "certificate:api.example.com")
        String dedupKey
) {
}
