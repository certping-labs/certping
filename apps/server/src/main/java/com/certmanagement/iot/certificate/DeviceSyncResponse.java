// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import java.time.OffsetDateTime;
import java.util.List;

/** Per-device acceptance report for an asynchronous Intune sync request. */
public record DeviceSyncResponse(
        int selectedDevices,
        int queuedDevices,
        int skippedDevices,
        List<DeviceResult> devices) {

    public DeviceSyncResponse {
        devices = devices == null ? List.of() : List.copyOf(devices);
    }

    public record DeviceResult(
            String deviceXref,
            String status,
            String reason,
            List<String> certificateXrefs,
            OffsetDateTime nextAllowedAt) {

        public DeviceResult {
            certificateXrefs = certificateXrefs == null
                    ? List.of() : List.copyOf(certificateXrefs);
        }
    }
}
