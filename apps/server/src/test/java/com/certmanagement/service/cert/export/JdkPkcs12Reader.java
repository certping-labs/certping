// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Reads a .pfx the way a customer's stock Java runtime does: the JDK's own {@code KeyStore("PKCS12")}
 * with no BouncyCastle registered. The JDK implementation resolves its PBES2 cipher by provider order,
 * so with BouncyCastle first it would decrypt with BouncyCastle's {@code PBEWithHmacSHA256AndAES_256}
 * and reject a valid AES file; that says nothing about the file, so the reader steps outside it.
 */
final class JdkPkcs12Reader {

    private static final String SUN_PROVIDER = "SUN";

    private JdkPkcs12Reader() {
    }

    /** What the JDK found: every alias, and the key and chain under {@code alias}. */
    record Contents(List<String> aliases, boolean isKeyEntry, Key key, Certificate[] chain) {
    }

    /**
     * @throws java.io.IOException as {@link KeyStore#load} does, e.g. for a wrong password
     */
    static Contents read(byte[] pfx, char[] password, String alias) throws Exception {
        return SecurityProviderModeExtension.callIn(SecurityProviderMode.NO_BOUNCY_CASTLE, () -> {
            KeyStore keyStore = KeyStore.getInstance("PKCS12", SUN_PROVIDER);
            keyStore.load(new ByteArrayInputStream(pfx), password);
            return new Contents(Collections.list(keyStore.aliases()), keyStore.isKeyEntry(alias),
                    keyStore.getKey(alias, password), keyStore.getCertificateChain(alias));
        });
    }
}
