// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

public enum AlertTypeEnum {

    CERTIFICATE_FAILURE("certificate_failure", "Certificate Failure"),
    DEPLOYMENT_FAILURE("deployment_failure",   "Deployment Failure");
    
    private final String value;
    private final String displayName;

    AlertTypeEnum(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public String getValue()       { return value; }
    public String getDisplayName() { return displayName; }
}
