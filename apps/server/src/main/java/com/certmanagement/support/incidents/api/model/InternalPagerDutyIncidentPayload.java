// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import tools.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;

@Schema(description = "Internal PagerDuty trigger payload. alertId is optional for internal callers.")
public record InternalPagerDutyIncidentPayload(
        @Schema(description = "Optional application alert id stored with the created incident record.", example = "12345")
        @JsonDeserialize(using = StrictLongDeserializer.class)
        @Positive Long alertId,
        @Schema(description = "Short incident summary shown in PagerDuty.", example = "api.example.com certificate expires in 5 days")
        @NotBlank @Size(max = 1024) String title,
        @Schema(description = "Source system or component responsible for the event.", example = "certping/certificate-monitor")
        @NotBlank @Size(max = 255) String source,
        @Schema(description = "PagerDuty event severity.", example = "CRITICAL")
        @NotNull PagerDutyIncidentSeverity severity,
        @Schema(description = "Optional deduplication key. When omitted, alertId is reused when present.", example = "certificate:api.example.com")
        @Size(max = 255) String dedupKey,
        @Schema(description = "Optional component name for PagerDuty event payload.", example = "certificate-monitor")
        @Size(max = 255) String component,
        @Schema(description = "Optional grouping value for PagerDuty event payload.", example = "production-certificates")
        @Size(max = 255) String group,
        @Schema(description = "Optional class value for PagerDuty event payload.", example = "certificate-expiry")
        @Size(max = 255) String className,
        @Schema(description = "Optional structured details sent to PagerDuty as custom_details. Up to 50 top-level fields are accepted.")
        @Size(max = 50) Map<String, Object> customDetails,
        @Schema(description = "Optional links attached to the PagerDuty incident.")
        @Valid @Size(max = 10) List<@Valid PagerDutyIncidentLink> links
) {
}
