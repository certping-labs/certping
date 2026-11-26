// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Schema(description = "Internal request for creating a PagerDuty incident for a specific organization.")
public record InternalCreatePagerDutyIncidentRequest(
        @Schema(description = "Target organization id.", example = "42")
        @NotNull @Positive Long orgId,
        @Schema(description = "PagerDuty incident payload to send through the organization's active PagerDuty integration.")
        @NotNull @Valid InternalPagerDutyIncidentPayload incident
) {
}
