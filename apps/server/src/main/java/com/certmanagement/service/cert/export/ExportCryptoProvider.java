// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

/**
 * The one JCA provider the export package parses, verifies and packages key material with.
 *
 * <p>Pinned rather than looked up because the JVM-wide provider order is not ours: a library or the
 * JVM's {@code java.security} configuration can register BouncyCastle at position 1, after which an
 * unqualified lookup returns BouncyCastle objects (an EC key reports {@code "ECDSA"}, not {@code "EC"})
 * where a JVM without it returns the JDK's. One explicit instance gives the same behaviour in both. It
 * is private: production code must never register BouncyCastle with {@code Security}.
 */
final class ExportCryptoProvider {

    static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();

    private ExportCryptoProvider() {
    }
}
