// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.AccessToken;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionRevocationServiceTest {

    private final UserRepository users = mock(UserRepository.class);
    private final RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
    private final AccessTokenBlacklistService blacklist = mock(AccessTokenBlacklistService.class);
    private final SessionRevocationService service = new SessionRevocationService(users, refreshTokens, blacklist);

    private static AccessToken token(int userId, Instant iat) {
        return new AccessToken("jti-" + userId, "u@x", userId, 1L, List.of(), List.of(), "LOCAL",
                Instant.now().plusSeconds(600), iat);
    }

    @Test
    void endingAllSessionsRevokesRefreshTokensRefusesOlderAccessTokensAndKeepsTheCallers() {
        AccessToken current = token(7, Instant.now());

        service.endAllSessions(7, current);

        verify(refreshTokens).revokeAllForUser(7);
        ArgumentCaptor<OffsetDateTime> at = ArgumentCaptor.forClass(OffsetDateTime.class);
        verify(users).markTokensValidAfter(eq(7), at.capture());
        assertThat(at.getValue().getNano()).as("whole seconds, like iat").isZero();
        verify(blacklist).exempt(current);
    }

    @Test
    void anotherUsersTokenIsNeverExempted() {
        service.endAllSessions(7, token(8, Instant.now()));
        verify(blacklist, never()).exempt(any());
    }

    @Test
    void aTokenIssuedBeforeTheInstantIsRefusedOneIssuedAtOrAfterItIsNot() {
        OffsetDateTime at = OffsetDateTime.of(2026, 10, 1, 12, 0, 0, 0, ZoneOffset.UTC);
        assertThat(SessionRevocationService.refuses(token(7, at.toInstant().minusSeconds(1)), at, blacklist)).isTrue();
        assertThat(SessionRevocationService.refuses(token(7, at.toInstant()), at, blacklist)).isFalse();
        assertThat(SessionRevocationService.refuses(token(7, at.toInstant().plusSeconds(5)), at, blacklist)).isFalse();
        assertThat(SessionRevocationService.refuses(token(7, at.toInstant().minusSeconds(60)), null, blacklist)).isFalse();
    }

    @Test
    void anExemptedTokenIsNotRefused() {
        OffsetDateTime at = OffsetDateTime.now(ZoneOffset.UTC);
        when(blacklist.isExempt("jti-7")).thenReturn(true);
        assertThat(SessionRevocationService.refuses(token(7, at.toInstant().minusSeconds(60)), at, blacklist)).isFalse();
    }
}
