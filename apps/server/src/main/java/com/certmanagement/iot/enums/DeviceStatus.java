// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.enums;

/**
 * CertPing's own device lifecycle.
 *
 * <p>ORPHANED is not deletion. A device gone from its platform may still hold a live
 * certificate, so it becomes a revocation candidate rather than disappearing.
 */
public enum DeviceStatus {
    REGISTERED,
    ORPHANED,
    DECOMMISSIONED
}
