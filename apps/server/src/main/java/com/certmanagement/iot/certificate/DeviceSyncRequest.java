// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;

/** Selects devices for an operator-requested Intune check-in. */
public record DeviceSyncRequest(
        @Valid List<@NotBlank @Size(max = 100) String> deviceXrefs) {

    public DeviceSyncRequest {
        deviceXrefs = deviceXrefs == null ? List.of() : List.copyOf(deviceXrefs);
    }
}
