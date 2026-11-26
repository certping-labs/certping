// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.domain;

public enum IntegrationProvider {
    SLACK,
    TEAMS,
    PAGERDUTY,
    SERVICENOW_ITSM;

    public boolean isWebhookProvider() {
        return this == SLACK || this == TEAMS;
    }

    public boolean supportsIncidentCreation() {
        return this == PAGERDUTY || this == SERVICENOW_ITSM;
    }
}
