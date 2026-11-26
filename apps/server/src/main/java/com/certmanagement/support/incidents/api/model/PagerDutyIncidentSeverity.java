// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

public enum PagerDutyIncidentSeverity {
    CRITICAL("critical"),
    ERROR("error"),
    WARNING("warning"),
    INFO("info");

    private final String pagerDutyValue;

    PagerDutyIncidentSeverity(String pagerDutyValue) {
        this.pagerDutyValue = pagerDutyValue;
    }

    public String pagerDutyValue() {
        return pagerDutyValue;
    }
}
