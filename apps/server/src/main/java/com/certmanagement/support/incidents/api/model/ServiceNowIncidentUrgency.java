// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

public enum ServiceNowIncidentUrgency {
    HIGH("1"),
    MEDIUM("2"),
    LOW("3");

    private final String serviceNowValue;

    ServiceNowIncidentUrgency(String serviceNowValue) {
        this.serviceNowValue = serviceNowValue;
    }

    public String serviceNowValue() {
        return serviceNowValue;
    }
}
