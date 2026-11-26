// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * A batch of device identities from one management platform.
 *
 * <p>Batched rather than per-device because a 50k-device tenant over single-device
 * POSTs is not viable. Callers page.
 */
public record IdentityRegistrationRequest(

        @NotBlank String sourceXref,

        /**
         * Groups a full-sync run so orphan detection knows which devices were expected.
         * Optional: incremental syncs and ad-hoc imports leave it null.
         */
        String syncXref,

        @NotEmpty
        @Size(max = 1000, message = "A batch may contain at most 1000 devices")
        @Valid List<DeviceIdentityPayload> devices
) {}
