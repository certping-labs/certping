// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.BlacklistedToken;
import com.certmanagement.entity.OutstandingToken;
import com.certmanagement.entity.User;
import com.certmanagement.repository.BlacklistedTokenRepository;
import com.certmanagement.repository.OutstandingTokenRepository;
import com.certmanagement.security.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock private OutstandingTokenRepository outstandingRepo;
    @Mock private BlacklistedTokenRepository blacklistedRepo;
    @Mock private JwtTokenProvider jwtTokenProvider;

    @InjectMocks private RefreshTokenService service;

    private final User aliceUser = User.builder().id(7).email("alice@example.com").build();
    private final String refreshToken = "refresh-jwt-with-jti";

    @Test
    void recordIssued_persists_outstanding_row_with_jti_and_expiry() {
        when(jwtTokenProvider.parseRefreshToken(refreshToken)).thenReturn(Optional.of(parsed("jti-1")));
        when(outstandingRepo.findByJti("jti-1")).thenReturn(Optional.empty());

        service.recordIssued(refreshToken, aliceUser, "LOCAL");

        ArgumentCaptor<OutstandingToken> captor = ArgumentCaptor.forClass(OutstandingToken.class);
        verify(outstandingRepo).save(captor.capture());
        assertThat(captor.getValue().getJti()).isEqualTo("jti-1");
        assertThat(captor.getValue().getUser()).isEqualTo(aliceUser);
        assertThat(captor.getValue().getToken()).isEqualTo(refreshToken);
        assertThat(captor.getValue().getAuthMethod()).isEqualTo("LOCAL");
    }

    @Test
    void recordIssued_persists_social_origin_when_passed() {
        when(jwtTokenProvider.parseRefreshToken(refreshToken)).thenReturn(Optional.of(parsed("jti-social")));
        when(outstandingRepo.findByJti("jti-social")).thenReturn(Optional.empty());

        service.recordIssued(refreshToken, aliceUser, "SOCIAL");

        ArgumentCaptor<OutstandingToken> captor = ArgumentCaptor.forClass(OutstandingToken.class);
        verify(outstandingRepo).save(captor.capture());
        assertThat(captor.getValue().getAuthMethod()).isEqualTo("SOCIAL");
    }

    @Test
    void recordIssued_defaults_to_LOCAL_when_authMethod_null() {
        when(jwtTokenProvider.parseRefreshToken(refreshToken)).thenReturn(Optional.of(parsed("jti-default")));
        when(outstandingRepo.findByJti("jti-default")).thenReturn(Optional.empty());

        service.recordIssued(refreshToken, aliceUser, null);

        ArgumentCaptor<OutstandingToken> captor = ArgumentCaptor.forClass(OutstandingToken.class);
        verify(outstandingRepo).save(captor.capture());
        assertThat(captor.getValue().getAuthMethod()).isEqualTo("LOCAL");
    }

    @Test
    void recordIssued_skips_a_token_that_does_not_verify() {
        when(jwtTokenProvider.parseRefreshToken(refreshToken)).thenReturn(Optional.empty());

        service.recordIssued(refreshToken, aliceUser, "LOCAL");

        verify(outstandingRepo, never()).save(any());
    }

    @Test
    void recordIssued_is_idempotent_when_already_persisted() {
        when(jwtTokenProvider.parseRefreshToken(refreshToken)).thenReturn(Optional.of(parsed("jti-1")));
        when(outstandingRepo.findByJti("jti-1")).thenReturn(Optional.of(new OutstandingToken()));

        service.recordIssued(refreshToken, aliceUser, "LOCAL");

        verify(outstandingRepo, never()).save(any());
    }

    @Test
    void blacklist_inserts_blacklist_row_when_outstanding_exists() {
        OutstandingToken outstanding = OutstandingToken.builder().id(42L).jti("jti-2").build();
        when(blacklistedRepo.existsByJti("jti-2")).thenReturn(false);
        when(outstandingRepo.findByJti("jti-2")).thenReturn(Optional.of(outstanding));

        service.blacklist(parsed("jti-2"));

        ArgumentCaptor<BlacklistedToken> captor = ArgumentCaptor.forClass(BlacklistedToken.class);
        verify(blacklistedRepo).save(captor.capture());
        assertThat(captor.getValue().getToken()).isEqualTo(outstanding);
    }

    @Test
    void blacklist_is_idempotent_when_already_blacklisted() {
        when(blacklistedRepo.existsByJti("jti-2")).thenReturn(true);

        service.blacklist(parsed("jti-2"));

        verify(blacklistedRepo, never()).save(any());
    }

    @Test
    void blacklist_skips_silently_when_outstanding_row_missing() {
        // Legacy token issued before persistence was wired — can't be blacklisted.
        when(blacklistedRepo.existsByJti("jti-orphan")).thenReturn(false);
        when(outstandingRepo.findByJti("jti-orphan")).thenReturn(Optional.empty());

        service.blacklist(parsed("jti-orphan"));

        verify(blacklistedRepo, never()).save(any());
    }

    @Test
    void isBlacklisted_returns_false_for_null_jti() {
        assertThat(service.isBlacklisted(parsed(null))).isFalse();
    }

    @Test
    void isBlacklisted_delegates_to_repo_when_jti_present() {
        when(blacklistedRepo.existsByJti("jti-3")).thenReturn(true);
        assertThat(service.isBlacklisted(parsed("jti-3"))).isTrue();
    }

    @Test
    void revokeAllForUser_blacklists_all_active_tokens() {
        OutstandingToken t1 = OutstandingToken.builder().id(1L).jti("a").build();
        OutstandingToken t2 = OutstandingToken.builder().id(2L).jti("b").build();
        when(outstandingRepo.findActiveByUserId(eq7(), any())).thenReturn(List.of(t1, t2));

        int count = service.revokeAllForUser(7);

        assertThat(count).isEqualTo(2);
        ArgumentCaptor<List<BlacklistedToken>> captor = ArgumentCaptor.forClass(List.class);
        verify(blacklistedRepo).saveAll(captor.capture());
        assertThat(captor.getValue()).hasSize(2);
    }

    @Test
    void revokeAllForUser_zero_for_null_userId() {
        assertThat(service.revokeAllForUser(null)).isEqualTo(0);
        verify(blacklistedRepo, never()).saveAll(anyList());
    }

    private static com.certmanagement.security.RefreshToken parsed(String jti) {
        return new com.certmanagement.security.RefreshToken(jti, "alice@example.com", 7, null,
                java.time.Instant.now().plus(java.time.Duration.ofDays(1)));
    }

    private static Integer eq7() {
        return org.mockito.ArgumentMatchers.eq(7);
    }
}
