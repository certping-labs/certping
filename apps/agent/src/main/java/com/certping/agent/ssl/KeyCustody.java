// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

/** Who holds a certificate's private key; mirrors the server's enum of the same name. */
public enum KeyCustody {
    PLATFORM_HELD,
    CUSTOMER_HELD;

    /** The custody a message names; a message that names none is platform-held, as every message was before. */
    public static KeyCustody fromMessage(String value) {
        return value != null && CUSTOMER_HELD.name().equalsIgnoreCase(value.trim()) ? CUSTOMER_HELD : PLATFORM_HELD;
    }

    /** The custody of a bundle: platform-held when the private key was stored with the chain. */
    public static KeyCustody ofStoredKey(String privateKeyPem) {
        return privateKeyPem == null ? CUSTOMER_HELD : PLATFORM_HELD;
    }
}
