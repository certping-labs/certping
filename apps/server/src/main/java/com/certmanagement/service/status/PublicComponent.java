// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

/** The public components, in page order. Ids and names are a public contract the frontends key on. */
public enum PublicComponent {

    API("api", "API and sign-in", ComponentStatus.MAJOR_OUTAGE),
    // Work waits in the message queue while these are down and resumes, so it is a partial outage.
    NOTIFICATIONS("notifications", "Email notifications", ComponentStatus.PARTIAL_OUTAGE),
    CERTIFICATES("certificates", "Certificate issuance and renewal", ComponentStatus.PARTIAL_OUTAGE);

    private final String id;
    private final String publicName;
    private final ComponentStatus failureStatus;

    PublicComponent(String id, String publicName, ComponentStatus failureStatus) {
        this.id = id;
        this.publicName = publicName;
        this.failureStatus = failureStatus;
    }

    public String id() {
        return id;
    }

    public String publicName() {
        return publicName;
    }

    ComponentStatus failureStatus() {
        return failureStatus;
    }
}
