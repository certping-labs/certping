// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

public enum AlertStatus {
    NEW("new",                         "New"),
    PENDING("pending",                 "Pending"),
    ISSUED("issued",                   "Issued"),
    FAILED("failed",                   "Failed"),
    REVOKED("revoked",                 "Revoked"),
    EXPIRED("expired",                 "Expired"),
    DELETED("deleted",                 "Deleted"),
    RENEWAL_PENDING("renewal_pending", "Renewal Pending"),
    RENEWAL_SUCCESS("renewal_success", "Renewal Success"),
    RENEWAL_FAILED("renewal_failed",   "Renewal Failed");

    private final String value;
    private final String displayName;

    AlertStatus(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public String getValue()       { return value; }
    public String getDisplayName() { return displayName; }
}
