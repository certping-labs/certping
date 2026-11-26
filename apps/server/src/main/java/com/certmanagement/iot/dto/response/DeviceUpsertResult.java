// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

/** Per-device outcome, so one bad row does not fail an entire batch. */
public record DeviceUpsertResult(
        String externalId,
        String deviceXref,
        UpsertOutcome outcome,
        String error
) {
    public static DeviceUpsertResult ok(String externalId, String deviceXref, UpsertOutcome outcome) {
        return new DeviceUpsertResult(externalId, deviceXref, outcome, null);
    }

    public static DeviceUpsertResult failed(String externalId, String error) {
        return new DeviceUpsertResult(externalId, null, UpsertOutcome.FAILED, error);
    }
}
