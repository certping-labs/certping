// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

import java.time.OffsetDateTime;
import java.util.Map;

public record DeviceSourceEventDto(
        String eventXref,
        String eventType,
        String eventStatus,
        Map<String, Object> detail,
        OffsetDateTime occurredAt,
        OffsetDateTime receivedAt,
        String correlationId
) {}
