// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import io.jsonwebtoken.security.Jwks;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

/** RSA key material for JWT tests, in the same shapes the environment supplies. */
public final class JwtTestKeys {

    private JwtTestKeys() {
    }

    public static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** PKCS#8 PEM, as {@code openssl genpkey} writes it. */
    public static String privatePem(KeyPair pair) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }

    public static String publicJwk(String kid, KeyPair pair) {
        return Jwks.json(Jwks.builder().key((RSAPublicKey) pair.getPublic()).id(kid).build());
    }

    public static String jwks(String... jwks) {
        return Arrays.stream(jwks).collect(Collectors.joining(",", "{\"keys\":[", "]}"));
    }
}
