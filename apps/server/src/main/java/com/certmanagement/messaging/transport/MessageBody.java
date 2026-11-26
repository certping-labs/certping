// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * The immutable body of a {@link TransportMessage}: a byte sequence that reads back as UTF-8 text.
 */
public final class MessageBody {

    private final byte[] bytes;

    private MessageBody(byte[] bytes) {
        this.bytes = bytes;
    }

    /** A body holding {@code text} encoded as UTF-8. */
    public static MessageBody fromString(String text) {
        Objects.requireNonNull(text, "text");
        return new MessageBody(text.getBytes(StandardCharsets.UTF_8));
    }

    /** A body holding a copy of {@code bytes}. */
    public static MessageBody fromBytes(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return new MessageBody(bytes.clone());
    }

    /** A copy of the raw bytes. */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /** The body decoded as UTF-8. */
    @Override
    public String toString() {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof MessageBody body && Arrays.equals(bytes, body.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
