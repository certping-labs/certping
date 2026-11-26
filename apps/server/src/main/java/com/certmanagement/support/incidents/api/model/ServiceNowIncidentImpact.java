// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

public enum ServiceNowIncidentImpact {
    HIGH("1"),
    MEDIUM("2"),
    LOW("3");

    private final String serviceNowValue;

    ServiceNowIncidentImpact(String serviceNowValue) {
        this.serviceNowValue = serviceNowValue;
    }

    public String serviceNowValue() {
        return serviceNowValue;
    }
}
