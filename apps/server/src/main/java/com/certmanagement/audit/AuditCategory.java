// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

/** The groups the customer audit page filters by. {@link #PLATFORM} is for internal rows only. */
public enum AuditCategory {
    ACCESS_CONTROL("Access control"),
    AUTHENTICATION("Sign-in"),
    ORGANIZATION("Organization"),
    CERTIFICATES("Certificates"),
    DEPLOYMENTS("Deployments"),
    CREDENTIALS("Credentials"),
    DISCOVERY("Discovery"),
    MONITORING("Monitoring"),
    MACHINE_IDENTITY("Machine identity"),
    INTEGRATIONS("Integrations"),
    SUPPORT("Support"),
    ACCESS("Sensitive access"),
    PLATFORM("Platform");

    private final String label;

    AuditCategory(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
