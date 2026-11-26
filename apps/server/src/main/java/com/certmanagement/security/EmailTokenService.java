// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Issues and validates the short-lived JWTs of password-reset links.
 *
 * <p>They have their own HMAC-SHA256 signing secret, distinct from the primary access/refresh
 * secret used by {@link JwtTokenProvider}, and carry a type claim that is checked, so a reset token
 * can't be replayed as an access token and no other token can be used as a reset token.</p>
 *
 * <p>Tokens are stateless — not persisted to the database. They are bound to one user
 * (by {@code email} claim) and expire on their own.</p>
 */
@Slf4j
@Component
public class EmailTokenService {

    private static final String CLAIM_TOKEN_TYPE = "type";
    private static final String CLAIM_EMAIL      = "email";
    /** Reset tokens only: {@link #passwordFingerprint} of the hash the token was issued against. */
    public static final String CLAIM_PASSWORD_FINGERPRINT = "pwd";

    static final int MIN_SECRET_BYTES = 32;
    private static final int FINGERPRINT_LENGTH = 22;

    public static final String TYPE_PASSWORD_RESET = "password_reset";

    @Value("${jwt.password-reset-secret:}")
    private String passwordResetSecret;

    @Value("${jwt.password-reset-expiry-hours:1}")
    private int passwordResetExpiryHours;

    private SecretKey passwordResetKey;

    @PostConstruct
    public void init() {
        if (!StringUtils.hasText(passwordResetSecret)) {
            log.warn("jwt.password-reset-secret is not configured — password-reset tokens "
                    + "will fail to issue. Set PASSWORD_RESET_TOKEN_SECRET (≥32 bytes) before forgot-password is enabled.");
        } else {
            this.passwordResetKey = Keys.hmacShaKeyFor(requireKeyLength(passwordResetSecret, "PASSWORD_RESET_TOKEN_SECRET"));
        }
    }

    /**
     * HS256 needs a key of at least 256 bits. A shorter secret is refused at startup rather than padded:
     * padding with zeros leaves the key exactly as guessable as the short secret.
     */
    static byte[] requireKeyLength(String secret, String setting) {
        byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
        if (raw.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(setting + " must be at least " + MIN_SECRET_BYTES
                    + " bytes (it is " + raw.length + "); generate one with: openssl rand -hex 24");
        }
        return raw;
    }

    /**
     * A short fingerprint of a password hash ({@code null} for an account without a password): the
     * first 22 characters of the unpadded base64url SHA-256 of its UTF-8 bytes. A reset token carries the
     * fingerprint of the hash it was issued against, so it stops working as soon as the password changes,
     * including by its own use. Anything that can read the users row can compute it, e.g.
     * {@code printf '%s' "$hash" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=' | cut -c1-22}.
     */
    public static String passwordFingerprint(String passwordHash) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((passwordHash == null ? "" : passwordHash).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).substring(0, FINGERPRINT_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // ── Password reset ──────────────────────────────────────────────────────

    /**
     * A reset token for the account, bound to its current password hash ({@link #passwordFingerprint}),
     * so it works once: the reset changes the hash, and so does any other password change.
     */
    public String issuePasswordResetToken(String email, String currentPasswordHash) {
        return issue(email, TYPE_PASSWORD_RESET, passwordResetKey,
                passwordResetExpiryHours * 3600L * 1000L, passwordFingerprint(currentPasswordHash));
    }

    /** Verifies a reset token; {@link ParsedEmailToken#getPasswordFingerprint()} is null when it has none. */
    public ParsedEmailToken parsePasswordResetToken(String token) {
        return parse(token, TYPE_PASSWORD_RESET, passwordResetKey);
    }

    // ── Internals ───────────────────────────────────────────────────────────

    private String issue(String email, String type, SecretKey key, long ttlMillis, String passwordFingerprint) {
        if (key == null) {
            throw new IllegalStateException("Signing key for '" + type + "' tokens is not configured");
        }
        Date now = new Date();
        JwtBuilder builder = Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + ttlMillis))
                .id(UUID.randomUUID().toString())
                .claim(CLAIM_EMAIL, email)
                .claim(CLAIM_TOKEN_TYPE, type);
        if (passwordFingerprint != null) {
            builder.claim(CLAIM_PASSWORD_FINGERPRINT, passwordFingerprint);
        }
        return builder.signWith(key).compact();
    }

    private ParsedEmailToken parse(String token, String expectedType, SecretKey key) {
        if (key == null) {
            throw new IllegalStateException("Signing key for '" + expectedType + "' tokens is not configured");
        }
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String actualType = claims.get(CLAIM_TOKEN_TYPE, String.class);
            if (!expectedType.equals(actualType)) {
                throw new EmailTokenException(EmailTokenError.INVALID, "Wrong token type");
            }
            String email = claims.get(CLAIM_EMAIL, String.class);
            if (!StringUtils.hasText(email)) {
                throw new EmailTokenException(EmailTokenError.INVALID, "Missing email claim");
            }
            return new ParsedEmailToken(email, claims.getId(), claims.get(CLAIM_PASSWORD_FINGERPRINT, String.class));
        } catch (ExpiredJwtException e) {
            throw new EmailTokenException(EmailTokenError.EXPIRED, "Token expired");
        } catch (JwtException e) {
            throw new EmailTokenException(EmailTokenError.INVALID, "Token invalid: " + e.getMessage());
        }
    }

    @Getter
    public static final class ParsedEmailToken {
        private final String email;
        private final String jti;
        /** The {@code pwd} claim of a reset token, or null. */
        private final String passwordFingerprint;

        public ParsedEmailToken(String email, String jti) {
            this(email, jti, null);
        }

        public ParsedEmailToken(String email, String jti, String passwordFingerprint) {
            this.email = email;
            this.jti = jti;
            this.passwordFingerprint = passwordFingerprint;
        }
    }

    public enum EmailTokenError { EXPIRED, INVALID }

    /** Thrown when a reset token fails validation. Controller maps to 400. */
    public static class EmailTokenException extends RuntimeException {
        private final EmailTokenError error;

        public EmailTokenException(EmailTokenError error, String message) {
            super(message);
            this.error = error;
        }

        public EmailTokenError getError() { return error; }
    }
}
