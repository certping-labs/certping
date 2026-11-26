// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

import java.time.OffsetDateTime;

/** One row in the device inventory table. */
public record DeviceListItem(
        String deviceXref,
        String deviceName,
        String serialNumber,
        String deviceClass,
        String operatingSystem,
        String osVersion,
        String model,
        String ownerUpn,
        String ownerDisplayName,
        String complianceState,
        String status,
        String platformDisplayName,
        OffsetDateTime lastSeenInSourceAt
) {}
