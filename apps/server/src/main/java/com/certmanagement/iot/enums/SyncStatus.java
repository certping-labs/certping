// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.enums;

/**
 * Outcome of a sync run. PARTIAL matters: Graph throttling routinely returns
 * some pages and not others, which is neither success nor failure.
 */
public enum SyncStatus {
    PENDING,
    RUNNING,
    OK,
    PARTIAL,
    FAILED
}
