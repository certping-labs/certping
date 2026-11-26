// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * The two JVM-wide provider lists the export must behave identically under: the bare JDK and
 * BouncyCastle first (as a library or the JVM's {@code java.security} configuration can install it).
 */
enum SecurityProviderMode {

    /** No BouncyCastle registered, including one left behind by an application context booted earlier. */
    NO_BOUNCY_CASTLE("no BouncyCastle provider registered") {
        @Override
        void apply() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    },

    /** A fresh BouncyCastle at position 1, where a library that registers it puts it. */
    BOUNCY_CASTLE_FIRST("BouncyCastle registered at position 1") {
        @Override
        void apply() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    };

    private final String displayName;

    SecurityProviderMode(String displayName) {
        this.displayName = displayName;
    }

    String displayName() {
        return displayName;
    }

    /** Rearranges {@link Security}'s provider list for this mode; the caller restores it. */
    abstract void apply();
}
