// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.enums;

/** Device ownership — not PII; lives on the core, not the owner table. */
public enum DeviceOwnership {
    COMPANY,
    PERSONAL,
    UNKNOWN
}
