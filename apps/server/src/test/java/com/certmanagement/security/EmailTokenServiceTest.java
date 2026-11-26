// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailTokenServiceTest {

    private static final String RESET_SECRET = "password-reset-secret-padded-to-be-long-enough-for-hs256";

    private EmailTokenService service;

    @BeforeEach
    void setUp() {
        service = new EmailTokenService();
        ReflectionTestUtils.setField(service, "passwordResetSecret", RESET_SECRET);
        ReflectionTestUtils.setField(service, "passwordResetExpiryHours", 1);
        service.init();
    }

    @Test
    void password_reset_token_roundtrips() {
        String token = service.issuePasswordResetToken("bob@example.com", "HASH-1");
        EmailTokenService.ParsedEmailToken parsed = service.parsePasswordResetToken(token);
        assertThat(parsed.getEmail()).isEqualTo("bob@example.com");
        assertThat(parsed.getJti()).isNotBlank();
    }

    @Test
    void password_reset_token_carries_the_fingerprint_of_the_hash_it_was_issued_for() {
        String token = service.issuePasswordResetToken("bob@example.com", "HASH-1");
        EmailTokenService.ParsedEmailToken parsed = service.parsePasswordResetToken(token);
        assertThat(parsed.getPasswordFingerprint())
                .isEqualTo(EmailTokenService.passwordFingerprint("HASH-1"))
                .isNotEqualTo(EmailTokenService.passwordFingerprint("HASH-2"))
                .hasSize(22);
    }

    @Test
    void password_fingerprint_matches_the_documented_shell_recipe() throws Exception {
        // printf '%s' "HASH-1" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=' | cut -c1-22
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest("HASH-1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String expected = java.util.Base64.getEncoder().encodeToString(digest)
                .replace('+', '-').replace('/', '_').replace("=", "").substring(0, 22);
        assertThat(EmailTokenService.passwordFingerprint("HASH-1")).isEqualTo(expected);
        assertThat(EmailTokenService.passwordFingerprint(null)).isEqualTo(EmailTokenService.passwordFingerprint(""));
    }

    @Test
    void a_secret_shorter_than_32_bytes_refuses_to_start() {
        EmailTokenService weak = new EmailTokenService();
        ReflectionTestUtils.setField(weak, "passwordResetSecret", "0123456789abcdef0123456789abcde");
        assertThatThrownBy(weak::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("PASSWORD_RESET_TOKEN_SECRET");
    }

    @Test
    void a_token_of_another_type_signed_with_the_reset_key_is_rejected() {
        String otherType = Jwts.builder()
                .subject("alice@example.com")
                .claim("email", "alice@example.com")
                .claim("type", "email_verification")
                .expiration(new java.util.Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(RESET_SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                .compact();
        assertThatThrownBy(() -> service.parsePasswordResetToken(otherType))
                .isInstanceOf(EmailTokenService.EmailTokenException.class)
                .matches(e -> ((EmailTokenService.EmailTokenException) e).getError()
                        == EmailTokenService.EmailTokenError.INVALID);
    }

    @Test
    void malformed_token_rejected() {
        assertThatThrownBy(() -> service.parsePasswordResetToken("not.a.real.jwt"))
                .isInstanceOf(EmailTokenService.EmailTokenException.class);
    }

    @Test
    void cross_secret_signature_rejected() {
        // A token issued by a different EmailTokenService instance (different secret)
        // must not validate against ours.
        EmailTokenService other = new EmailTokenService();
        ReflectionTestUtils.setField(other, "passwordResetSecret",
                "another-different-secret-padded-to-32-bytes-please-thx");
        ReflectionTestUtils.setField(other, "passwordResetExpiryHours", 1);
        other.init();
        String foreignToken = other.issuePasswordResetToken("alice@example.com", "HASH-1");

        assertThatThrownBy(() -> service.parsePasswordResetToken(foreignToken))
                .isInstanceOf(EmailTokenService.EmailTokenException.class);
    }

    @Test
    void missing_signing_key_fails_loudly_on_issue() {
        EmailTokenService bare = new EmailTokenService();
        ReflectionTestUtils.setField(bare, "passwordResetSecret", "");
        bare.init();
        assertThatThrownBy(() -> bare.issuePasswordResetToken("a@b.com", "HASH-1"))
                .isInstanceOf(IllegalStateException.class);
    }
}
