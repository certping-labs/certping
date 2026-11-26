// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Derives the 64-bit keys of this package's Postgres advisory locks from namespaced names. */
final class AdvisoryLockKeys {

    private AdvisoryLockKeys() {
    }

    /**
     * The first eight bytes of SHA-256 over {@code name}: stable across pods and releases, and a
     * collision only makes two unrelated names wait on each other.
     */
    static long keyOf(String name) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(name.getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.wrap(digest, 0, Long.BYTES).getLong();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", impossible);
        }
    }
}
