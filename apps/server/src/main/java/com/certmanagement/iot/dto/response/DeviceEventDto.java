// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

import java.time.OffsetDateTime;
import java.util.Map;

/** One entry in a device's history. */
public record DeviceEventDto(
        String eventXref,
        String eventType,
        String eventStatus,
        String eventMessage,
        String actorSource,
        Long actorUserId,
        Map<String, Object> detail,
        OffsetDateTime occurredAt,
        String correlationId
) {}
