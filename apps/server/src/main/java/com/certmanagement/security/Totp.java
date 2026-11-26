// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Time-based one-time passwords (RFC 6238 over RFC 4226): HMAC-SHA1, 30-second steps, six digits, which
 * is what every authenticator app defaults to. No library: the algorithm is forty lines and the Base32
 * alphabet the apps read is here too.
 */
public final class Totp {

    public static final int STEP_SECONDS = 30;
    public static final int DIGITS = 6;
    /** Steps either side of now a code is accepted for: one, so clock drift of up to 30 s passes. */
    public static final int WINDOW = 1;
    public static final int SECRET_BYTES = 20;

    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Totp() {
    }

    /** A fresh 160-bit secret, the length RFC 4226 recommends for HMAC-SHA1. */
    public static byte[] newSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        return secret;
    }

    /** The step {@code epochSeconds} falls in. */
    public static long step(long epochSeconds) {
        return Math.floorDiv(epochSeconds, STEP_SECONDS);
    }

    /** The six-digit code for {@code step}, zero-padded. */
    public static String code(byte[] secret, long step) {
        byte[] message = new byte[8];
        long value = step;
        for (int i = 7; i >= 0; i--) {
            message[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        byte[] hash;
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            hash = mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 is unavailable", e);
        }
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        int otp = binary % 1_000_000;
        return String.format(Locale.ROOT, "%06d", otp);
    }

    /**
     * The step {@code code} is valid for, within {@link #WINDOW} steps of {@code epochSeconds} and after
     * {@code lastUsedStep}, or {@code null} when it is not. A step is only ever accepted once, so the same
     * code cannot be replayed inside its window.
     */
    public static Long matchingStep(byte[] secret, String code, long epochSeconds, Long lastUsedStep) {
        String given = normalize(code);
        if (given == null) {
            return null;
        }
        long now = step(epochSeconds);
        for (long candidate = now - WINDOW; candidate <= now + WINDOW; candidate++) {
            if (lastUsedStep != null && candidate <= lastUsedStep) {
                continue;
            }
            if (constantTimeEquals(code(secret, candidate), given)) {
                return candidate;
            }
        }
        return null;
    }

    /** {@code code} with spaces removed, or null unless it is exactly six digits. */
    public static String normalize(String code) {
        if (code == null) {
            return null;
        }
        String digits = code.replace(" ", "").trim();
        if (digits.length() != DIGITS || !digits.chars().allMatch(Character::isDigit)) {
            return null;
        }
        return digits;
    }

    /** The {@code otpauth://} URI authenticator apps enroll from. */
    public static String otpauthUri(String issuer, String accountName, byte[] secret) {
        String label = encode(issuer) + ":" + encode(accountName);
        return "otpauth://totp/" + label
                + "?secret=" + base32(secret)
                + "&issuer=" + encode(issuer)
                + "&algorithm=SHA1&digits=" + DIGITS + "&period=" + STEP_SECONDS;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** RFC 4648 Base32 without padding, the form authenticator apps accept when typed by hand. */
    public static String base32(byte[] bytes) {
        StringBuilder out = new StringBuilder((bytes.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : bytes) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(BASE32.charAt((buffer >> (bits - 5)) & 0x1f));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(BASE32.charAt((buffer << (5 - bits)) & 0x1f));
        }
        return out.toString();
    }

    /** The bytes of a Base32 string (padding and spaces ignored, case ignored). */
    public static byte[] fromBase32(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : text.toUpperCase(Locale.ROOT).toCharArray()) {
            if (c == '=' || c == ' ' || c == '-') {
                continue;
            }
            int value = BASE32.indexOf(c);
            if (value < 0) {
                throw new IllegalArgumentException("Not Base32");
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    static boolean constantTimeEquals(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.US_ASCII);
        byte[] y = b.getBytes(StandardCharsets.US_ASCII);
        return java.security.MessageDigest.isEqual(x, y);
    }
}
