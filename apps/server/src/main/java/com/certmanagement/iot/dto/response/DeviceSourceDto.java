// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

public record DeviceSourceDto(
        String sourceXref,
        String provider,
        String sourceCategory,
        String connectionProfileRef,
        String displayName,
        String description,
        Map<String, Object> configurationMetadata,
        boolean syncEnabled,
        String status,
        OffsetDateTime firstAdvertisedAt,
        OffsetDateTime lastAdvertisedAt,
        Health health,
        Sync sync,
        long deviceCount
) {
    public record Health(
            String status,
            String reportedStatus,
            boolean stale,
            String providerStatus,
            String statusMessage,
            List<Permission> permissions,
            Map<String, Object> metadata,
            OffsetDateTime observedAt,
            OffsetDateTime receivedAt,
            OffsetDateTime staleAt,
            Long responseTimeMs
    ) {
        public record Permission(String name, boolean granted) {}
    }

    public record Sync(
            String syncXref,
            String status,
            OffsetDateTime requestedAt,
            OffsetDateTime startedAt,
            OffsetDateTime completedAt,
            Integer expectedDeviceCount,
            Integer processedDeviceCount,
            Integer failedDeviceCount,
            Integer processedBatchCount,
            Integer expectedBatchCount,
            boolean completionReceived,
            String lastError
    ) {}
}
