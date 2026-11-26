// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

/**
 * Identifies the system component that wrote a {@code certificate_events} row or published
 * a notification message.
 *
 * <p>The stored string value (returned by {@link #value()}) contains hyphens and therefore differs
 * from the enum name. Always call {@link #value()} — never {@link #name()} — when a {@code String}
 * is required.
 */
public enum EventSource {

    CERT_MANAGER("certping-cert-manager"),
    /** Stored on event rows; kept as written by earlier versions so existing rows still match. */
    SCHEDULER("certping-scheduler"),
    AGENT("certping-agent");

    private final String value;

    EventSource(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
