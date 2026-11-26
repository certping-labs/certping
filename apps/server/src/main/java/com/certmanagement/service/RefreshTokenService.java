// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.BlacklistedToken;
import com.certmanagement.entity.OutstandingToken;
import com.certmanagement.entity.User;
import com.certmanagement.repository.BlacklistedTokenRepository;
import com.certmanagement.repository.OutstandingTokenRepository;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.RefreshToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Tracks issued refresh tokens and revokes them on logout / rotation.
 *
 * <p>Backing tables: {@code auth_refresh_tokens} for every issued token,
 * {@code auth_revoked_refresh_tokens} for revoked ones. JTI is the join key (UUID set
 * by {@link JwtTokenProvider#generateRefreshToken}).</p>
 *
 * <p>A token without a JTI cannot be revoked: {@link #isBlacklisted(String)} returns false for
 * it, and it works until it expires.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final OutstandingTokenRepository outstandingRepo;
    private final BlacklistedTokenRepository blacklistedRepo;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Persist a freshly-issued refresh token. Best-effort: never throws on dup-key.
     *
     * @param refreshToken the just-issued refresh JWT
     * @param user         the user the token was minted for
     * @param authMethod   session-origin tag — one of
     *                     {@link com.certmanagement.constants.JwtClaims#AUTH_METHOD_LOCAL} or
     *                     {@link com.certmanagement.constants.JwtClaims#AUTH_METHOD_SSO}.
     */
    @Transactional
    public void recordIssued(String refreshToken, User user, String authMethod) {
        if (refreshToken == null || user == null) return;
        RefreshToken parsed = jwtTokenProvider.parseRefreshToken(refreshToken).orElse(null);
        if (parsed == null || parsed.jti() == null) {
            log.warn("Refusing to record a refresh token that does not verify");
            return;
        }
        String jti = parsed.jti();
        if (outstandingRepo.findByJti(jti).isPresent()) {
            return; // idempotent — same token can be persisted twice on retry
        }
        OffsetDateTime expiresAt = parsed.expiresAt().atOffset(ZoneOffset.UTC);
        OutstandingToken row = OutstandingToken.builder()
                .jti(jti)
                .token(refreshToken)
                .user(user)
                .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
                .expiresAt(expiresAt)
                .authMethod(authMethod != null ? authMethod
                        : com.certmanagement.constants.JwtClaims.AUTH_METHOD_LOCAL)
                .build();
        outstandingRepo.save(row);
    }

    /** Look up the recorded {@code auth_method} for a refresh token, or null if not on file. */
    public String getRecordedAuthMethod(RefreshToken refreshToken) {
        String jti = refreshToken.jti();
        if (jti == null) return null;
        return outstandingRepo.findByJti(jti)
                .map(OutstandingToken::getAuthMethod)
                .orElse(null);
    }

    /** Mark a refresh token's jti as revoked. Idempotent. */
    @Transactional
    public void blacklist(RefreshToken refreshToken) {
        blacklistByJti(refreshToken.jti());
    }

    @Transactional
    public void blacklistByJti(String jti) {
        if (jti == null) return;
        if (blacklistedRepo.existsByJti(jti)) return;

        Optional<OutstandingToken> outstandingOpt = outstandingRepo.findByJti(jti);
        if (outstandingOpt.isEmpty()) {
            // No outstanding row for this JTI: blacklisting needs one (FK constraint), so the
            // token stays valid until it expires.
            log.debug("Cannot blacklist jti={} — no matching outstanding row", jti);
            return;
        }
        BlacklistedToken row = BlacklistedToken.builder()
                .token(outstandingOpt.get())
                .blacklistedAt(OffsetDateTime.now(ZoneOffset.UTC))
                .build();
        blacklistedRepo.save(row);
        log.info("Blacklisted refresh token jti={}", jti);
    }

    public boolean isBlacklisted(RefreshToken refreshToken) {
        String jti = refreshToken.jti();
        return jti != null && blacklistedRepo.existsByJti(jti);
    }

    /**
     * Blacklist every currently-active refresh token for a user. Called after password reset
     * (force re-login everywhere) and could be called from "sign me out of all sessions" UX.
     * Returns the number of tokens revoked. Idempotent — already-blacklisted tokens are skipped.
     */
    @Transactional
    public int revokeAllForUser(Integer userId) {
        if (userId == null) return 0;
        List<OutstandingToken> active = outstandingRepo.findActiveByUserId(userId, OffsetDateTime.now(ZoneOffset.UTC));
        if (active.isEmpty()) return 0;
        List<BlacklistedToken> rows = new ArrayList<>(active.size());
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        for (OutstandingToken o : active) {
            rows.add(BlacklistedToken.builder().token(o).blacklistedAt(now).build());
        }
        blacklistedRepo.saveAll(rows);
        log.info("AUTH_EVENT revoke-all-tokens userId={} count={}", userId, rows.size());
        return rows.size();
    }
}
