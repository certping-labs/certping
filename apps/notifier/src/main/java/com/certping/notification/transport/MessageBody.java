// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** The body of a notification message: immutable bytes, read as UTF-8 text. */
public final class MessageBody {

    private final byte[] bytes;

    private MessageBody(byte[] bytes) {
        this.bytes = bytes;
    }

    public static MessageBody fromString(String text) {
        if (text == null) {
            throw new NullPointerException("text");
        }
        return new MessageBody(text.getBytes(StandardCharsets.UTF_8));
    }

    public static MessageBody fromBytes(byte[] bytes) {
        if (bytes == null) {
            throw new NullPointerException("bytes");
        }
        return new MessageBody(bytes.clone());
    }

    /** A copy of the body bytes. */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /** The body as UTF-8 text. */
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
