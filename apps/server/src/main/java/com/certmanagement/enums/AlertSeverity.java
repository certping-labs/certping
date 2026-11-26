// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

public enum AlertSeverity {
    CRITICAL("critical", "Critical"),
    WARNING("warning",   "Warning"),
    INFO("info",         "Info");

    private final String value;
    private final String displayName;

    AlertSeverity(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public String getValue()       { return value; }
    public String getDisplayName() { return displayName; }
}
