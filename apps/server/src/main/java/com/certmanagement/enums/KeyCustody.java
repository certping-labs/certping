// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

/** Who holds a certificate's private key. */
public enum KeyCustody {
    /** The agent generated the key and keeps it with the certificate: automatic renewal, deployment and PKCS#12. */
    PLATFORM_HELD,
    /** The customer holds the key (shown once, or their own CSR); CertPing stores the certificate and chain only. */
    CUSTOMER_HELD;

    /** The custody an agent result names, empty when it names none or an unknown one. */
    public static java.util.Optional<KeyCustody> fromResponse(String value) {
        if (value == null || value.isBlank()) {
            return java.util.Optional.empty();
        }
        try {
            return java.util.Optional.of(valueOf(value.trim()));
        } catch (IllegalArgumentException unknown) {
            return java.util.Optional.empty();
        }
    }
}
