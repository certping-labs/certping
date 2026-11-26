// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CreateIotRevocationRequest(
        @NotNull IotRevocationReason reason,
        @Size(max = 500) String operatorNote) {
}
