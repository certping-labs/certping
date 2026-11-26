// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The ids of the request a notification message was published for, read from its application
 * properties. A value that is missing or not valid is null, so nothing a publisher sends reaches a
 * log line or a span unchecked.
 */
public record MessageIds(String correlationId, String requestId, String traceparent) {

    public static final String CORRELATION_ID = "correlationId";
    public static final String REQUEST_ID = "requestId";
    public static final String TRACEPARENT = "traceparent";

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private static final Pattern W3C_TRACEPARENT = Pattern.compile("[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}");

    public static MessageIds from(Map<String, Object> properties) {
        if (properties == null) {
            return new MessageIds(null, null, null);
        }
        return new MessageIds(valid(properties.get(CORRELATION_ID)), valid(properties.get(REQUEST_ID)),
                matching(W3C_TRACEPARENT, properties.get(TRACEPARENT)));
    }

    /** The id when it is at most 128 characters of letters, digits, '.', '_', ':' and '-', else null. */
    public static String valid(Object id) {
        return matching(ID, id);
    }

    /**
     * A publisher's key in the only form a log line may carry: the key itself when it is a valid
     * id, else a digest of it, so two lines about one key still match and nothing unchecked is
     * printed. Null for no key.
     */
    public static String loggable(String key) {
        if (key == null || key.isBlank()) {
            return null;
        }
        String valid = valid(key);
        return valid != null ? valid : "sha256:" + digest(key);
    }

    /** The properties a message carries these ids in; an id that is absent is left out. */
    public void writeTo(Map<String, Object> properties) {
        putIfPresent(properties, CORRELATION_ID, correlationId);
        putIfPresent(properties, REQUEST_ID, requestId);
        putIfPresent(properties, TRACEPARENT, traceparent);
    }

    private static void putIfPresent(Map<String, Object> properties, String key, String value) {
        if (value != null) {
            properties.put(key, value);
        }
    }

    private static String digest(String key) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String matching(Pattern pattern, Object value) {
        return value instanceof String text && pattern.matcher(text).matches() ? text : null;
    }
}
