// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

import java.util.List;

/** Summary of one ingest batch. */
public record IdentityRegistrationResult(
        String syncXref,
        int created,
        int updated,
        int unchanged,
        int failed,
        List<DeviceUpsertResult> results
) {}
