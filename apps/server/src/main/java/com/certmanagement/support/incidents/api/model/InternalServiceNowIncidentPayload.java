// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import tools.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

@Schema(description = "Internal ServiceNow incident create payload. alertId is optional for internal callers.")
public record InternalServiceNowIncidentPayload(
        @Schema(description = "Optional application alert id stored with the created incident record.", example = "12345")
        @JsonDeserialize(using = StrictLongDeserializer.class)
        @Positive Long alertId,
        @Schema(description = "Short description shown on the ServiceNow incident.", example = "api.example.com certificate expires in 5 days")
        @NotBlank @Size(max = 160) String shortDescription,
        @Schema(description = "Optional longer incident description.", example = "The production API certificate expires soon and needs urgent rotation.")
        @Size(max = 4000) String description,
        @Schema(description = "Optional incident impact value.", example = "HIGH", nullable = true)
        ServiceNowIncidentImpact impact,
        @Schema(description = "Optional incident urgency value.", example = "HIGH", nullable = true)
        ServiceNowIncidentUrgency urgency,
        @Schema(description = "Optional ServiceNow category.", example = "inquiry", nullable = true)
        @Size(max = 100) String category,
        @Schema(description = "Optional ServiceNow subcategory.", example = "certificate", nullable = true)
        @Size(max = 100) String subcategory,
        @Schema(description = "Optional assignment group sys_id, or display value when the target ServiceNow instance allows input display values.", example = "287ebd7da9fe198100f92cc8d1d2154e", nullable = true)
        @Size(max = 255) String assignmentGroup,
        @Schema(description = "Optional business service sys_id, or display value when the target ServiceNow instance allows input display values.", example = "26da329f0a0a0bb400f69d8159bc753c", nullable = true)
        @Size(max = 255) String businessService,
        @Schema(description = "Optional configuration item sys_id, or display value when the target ServiceNow instance allows input display values.", example = "3a6cdbdbc0a8016700a222a0f7900d1a", nullable = true)
        @Size(max = 255) String configurationItem,
        @Schema(description = "Optional caller user sys_id, or display value when the target ServiceNow instance allows input display values.", example = "46c6f9efa9fe198101ddf5eed9adf6e7", nullable = true)
        @Size(max = 255) String callerId,
        @Schema(description = "Optional external correlation identifier for deduplication or traceability. When omitted, alertId is reused when present.", example = "certificate:api.example.com", nullable = true)
        @Size(max = 255) String correlationId,
        @Schema(description = "Optional human-readable correlation label.", example = "api.example.com certificate alert", nullable = true)
        @Size(max = 255) String correlationDisplay,
        @Schema(description = "Optional additional comments.", example = "Raised automatically by Certping.", nullable = true)
        @Size(max = 4000) String comments,
        @Schema(description = "Optional work notes.", example = "Triggered from certificate monitoring pipeline.", nullable = true)
        @Size(max = 4000) String workNotes
) {
}
