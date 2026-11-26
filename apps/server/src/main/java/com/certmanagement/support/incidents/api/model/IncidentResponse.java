// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import com.certmanagement.support.incidents.domain.IncidentCreationSource;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

@Schema(description = "Stored incident history entry")
public record IncidentResponse(
        @Schema(description = "Local database identifier", example = "42")
        Long id,
        @Schema(description = "Provider used to create the incident", example = "PAGERDUTY")
        IntegrationProvider provider,
        @Schema(description = "Whether the incident came from the public or internal API", example = "PUBLIC_API")
        IncidentCreationSource source,
        @Schema(description = "Authenticated user id when available", example = "9", nullable = true)
        Long actorUserId,
        @Schema(description = "Application alert id", example = "12345", nullable = true)
        Long alertId,
        @Schema(description = "Short summary stored for quick history scans", example = "api.example.com certificate expires in 5 days")
        String summary,
        @Schema(description = "Provider-native incident id when available", example = "d977b66a4f411200adf9f8e18110c7b2", nullable = true)
        String externalIncidentId,
        @Schema(description = "Provider-native reference to open in the external system", example = "INC0010002")
        String externalReference,
        @Schema(description = "Provider UI or record URL when available", example = "https://example.service-now.com/nav_to.do?uri=incident.do?sys_id=d977b66a4f411200adf9f8e18110c7b2", nullable = true)
        String externalUrl,
        @Schema(description = "Creation timestamp", example = "2026-04-24T10:15:30Z")
        Instant createdAt
) {
}
