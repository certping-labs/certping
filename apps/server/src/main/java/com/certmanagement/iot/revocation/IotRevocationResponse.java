// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import java.time.OffsetDateTime;

public record IotRevocationResponse(
        String operationXref,
        String certificateXref,
        String status,
        String reason,
        String source,
        int attemptCount,
        OffsetDateTime requestedAt,
        OffsetDateTime completedAt,
        String errorCode,
        String errorMessage) {
}
