// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.cahealth;

import tools.jackson.databind.JsonNode;

import java.time.OffsetDateTime;
import java.util.List;

public record CaConnectorResponse(
        String connectorId,
        String caProvider,
        boolean enabled,
        /** The reported status, or STALE once the report is older than the health freshness window. */
        String status,
        String reportedStatus,
        boolean stale,
        OffsetDateTime staleAt,
        OffsetDateTime checkedAt,
        OffsetDateTime respondedAt,
        OffsetDateTime receivedAt,
        Long latencyMs,
        String endpoint,
        String authMethod,
        JsonNode product,
        List<String> capabilities,
        JsonNode profiles,
        JsonNode issues,
        int reportVersion) {
}
