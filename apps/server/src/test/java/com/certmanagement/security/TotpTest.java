// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class TotpTest {

    /** RFC 6238 appendix B test vectors for HMAC-SHA1 with the ASCII secret "12345678901234567890". */
    private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @Test
    void matchesRfc6238Vectors() {
        // The RFC lists eight digits; the last six are the six-digit code.
        assertThat(Totp.code(RFC_SECRET, Totp.step(59L))).isEqualTo("287082");
        assertThat(Totp.code(RFC_SECRET, Totp.step(1111111109L))).isEqualTo("081804");
        assertThat(Totp.code(RFC_SECRET, Totp.step(1234567890L))).isEqualTo("005924");
        assertThat(Totp.code(RFC_SECRET, Totp.step(20000000000L))).isEqualTo("353130");
    }

    @Test
    void acceptsOneStepOfDriftAndNeverTheSameStepTwice() {
        long now = 1234567890L;
        long step = Totp.step(now);
        String previous = Totp.code(RFC_SECRET, step - 1);
        String next = Totp.code(RFC_SECRET, step + 1);
        String twoAhead = Totp.code(RFC_SECRET, step + 2);

        assertThat(Totp.matchingStep(RFC_SECRET, previous, now, null)).isEqualTo(step - 1);
        assertThat(Totp.matchingStep(RFC_SECRET, next, now, null)).isEqualTo(step + 1);
        assertThat(Totp.matchingStep(RFC_SECRET, twoAhead, now, null)).isNull();
        // A step at or before the last accepted one is spent.
        assertThat(Totp.matchingStep(RFC_SECRET, previous, now, step - 1)).isNull();
        assertThat(Totp.matchingStep(RFC_SECRET, Totp.code(RFC_SECRET, step), now, step - 1)).isEqualTo(step);
    }

    @Test
    void normalizeAcceptsSpacesAndRejectsAnythingButSixDigits() {
        assertThat(Totp.normalize("123 456")).isEqualTo("123456");
        assertThat(Totp.normalize(" 123456 ")).isEqualTo("123456");
        assertThat(Totp.normalize("12345")).isNull();
        assertThat(Totp.normalize("12345a")).isNull();
        assertThat(Totp.normalize(null)).isNull();
    }

    @Test
    void base32RoundTripsAndOtpauthUriCarriesTheSecret() {
        byte[] secret = Totp.newSecret();
        assertThat(secret).hasSize(Totp.SECRET_BYTES);
        String encoded = Totp.base32(secret);
        assertThat(encoded).matches("[A-Z2-7]+");
        assertThat(Totp.fromBase32(encoded)).isEqualTo(secret);
        assertThat(Totp.fromBase32(encoded.toLowerCase() + "====")).isEqualTo(secret);

        String uri = Totp.otpauthUri("CertPing", "ada@example.com", secret);
        assertThat(uri).startsWith("otpauth://totp/CertPing:ada%40example.com?secret=" + encoded)
                .contains("issuer=CertPing").contains("digits=6").contains("period=30");
    }
}
