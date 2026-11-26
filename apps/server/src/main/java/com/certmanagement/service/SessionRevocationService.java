// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.AccessToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

/**
 * Ends a user's sessions before their tokens expire. Access tokens are stateless, so each user row carries
 * {@code tokens_valid_after}: {@link com.certmanagement.security.JwtAuthenticationFilter} reads it with the
 * account flags it already loads per request and refuses any access token issued before it. Refresh tokens
 * are revoked in their own table. A role or permission change ({@code RoleManagementService}) only moves
 * the instant: a refresh reads roles from the database, so the client's next refresh carries the new ones.
 *
 * <p>The instant is whole seconds, like the {@code iat} it is compared with: a token issued in the same
 * second as the revocation stays valid, so the tokens a request mints right after revoking still work.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionRevocationService {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenBlacklistService accessTokenBlacklistService;

    /**
     * Signs the user out everywhere (a password change or reset): every refresh token is revoked and every
     * access token issued before now is refused.
     *
     * @param keep the access token of the request making the change, which keeps working; null for none
     */
    public void endAllSessions(Integer userId, AccessToken keep) {
        if (userId == null) {
            return;
        }
        int revoked = refreshTokenService.revokeAllForUser(userId);
        userRepository.markTokensValidAfter(userId, now());
        if (keep != null && userId.equals(keep.userId())) {
            accessTokenBlacklistService.exempt(keep);
        }
        log.info("AUTH_EVENT sessions-ended userId={} revokedRefreshTokens={}", userId, revoked);
    }

    /**
     * Whether the user's {@code tokensValidAfter} refuses this token. A token without {@code iat} is
     * refused whenever an instant is set; the exemption is only looked up for a token that would be refused.
     */
    public static boolean refuses(AccessToken token, OffsetDateTime tokensValidAfter,
                                  AccessTokenBlacklistService exemptions) {
        if (tokensValidAfter == null) {
            return false;
        }
        Instant issuedAt = token.issuedAt();
        if (issuedAt != null && !issuedAt.isBefore(tokensValidAfter.toInstant())) {
            return false;
        }
        return exemptions == null || !exemptions.isExempt(token.jti());
    }

    /** The instant a revocation made now writes: whole seconds, like {@code iat}. */
    public static OffsetDateTime now() {
        return OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
    }
}
