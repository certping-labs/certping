// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.response;

/**
 * What an upsert did to one device.
 *
 * <p>UNCHANGED is load-bearing: without it a 5,000-device tenant synced hourly writes
 * 120,000 audit rows a day recording that nothing happened.
 */
public enum UpsertOutcome {
    CREATED,
    UPDATED,
    UNCHANGED,
    FAILED
}
