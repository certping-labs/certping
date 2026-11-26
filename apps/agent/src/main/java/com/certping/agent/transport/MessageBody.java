// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.transport;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * An immutable message body. The bytes are kept exactly as given, so a body built from bytes is
 * sent as those bytes and a body built from a string is its UTF-8 encoding.
 */
public final class MessageBody {

    private final byte[] bytes;

    private MessageBody(byte[] bytes) {
        this.bytes = bytes;
    }

    public static MessageBody fromString(String value) {
        return new MessageBody((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
    }

    public static MessageBody fromBytes(byte[] value) {
        return new MessageBody(value == null ? new byte[0] : value.clone());
    }

    /** A copy of the body bytes. */
    public byte[] toBytes() {
        return bytes.clone();
    }

    /** The body decoded as UTF-8. */
    @Override
    public String toString() {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof MessageBody other && Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
