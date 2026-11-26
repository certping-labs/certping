// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/** Organization inventory analytics for dashboard cards, charts, and filters. */
public record IotSummary(
        long totalDevices,
        long activeDevices,
        Map<String, Long> byStatus,
        Map<String, Long> byProvider,
        List<SourceDeviceCount> bySource,
        Map<String, Long> byDeviceClass,
        Map<String, Long> byOwnership,
        Map<String, Long> byOperatingSystem,
        Map<String, Long> byComplianceState,
        BooleanBreakdown encryption,
        BooleanBreakdown supervision,
        SourceOverview sources,
        OffsetDateTime lastSyncCompletedAt
) {
    public record SourceDeviceCount(
            String sourceXref,
            String displayName,
            String provider,
            long deviceCount
    ) {}

    public record BooleanBreakdown(long yes, long no, long unknown) {}

    public record SourceOverview(
            long total,
            long syncEnabled,
            long healthy,
            long degraded,
            long unhealthy,
            long stale,
            long unknown
    ) {}
}
