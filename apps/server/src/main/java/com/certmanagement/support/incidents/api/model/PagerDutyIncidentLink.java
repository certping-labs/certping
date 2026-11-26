// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PagerDutyIncidentLink(
        @Schema(description = "Absolute URL shown in PagerDuty incident links.", example = "https://certping.example.com/incidents/123")
        @NotBlank @Size(max = 2048) String href,
        @Schema(description = "Short label shown for the link in PagerDuty.", example = "Open incident")
        @NotBlank @Size(max = 255) String text
) {
}
