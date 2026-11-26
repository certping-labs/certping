// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.security.AccessToken;
import com.certmanagement.security.JwtTokenProvider;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.data.redis.autoconfigure.DataRedisProperties;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccessTokenBlacklistServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-24T10:00:00Z");

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final AccessTokenBlacklistService service =
            new AccessTokenBlacklistService(redis, meters, Clock.fixed(NOW, ZoneOffset.UTC));

    private static AccessToken token(String jti, Instant expiresAt) {
        return new AccessToken(jti, "u@example.com", 7, 42L, List.of(), List.of(), "LOCAL", expiresAt);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"${REDIS_HOST}"})
    void refusesToStartWithoutARedisHost(String host) {
        DataRedisProperties properties = new DataRedisProperties();
        properties.setHost(host);

        assertThatThrownBy(() -> new AccessTokenBlacklistService(redis, meters, properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("REDIS_HOST");
    }

    @Test
    void revokeKeepsTheEntryForTheTokensRemainingLifetimePlusAMinute() {
        when(redis.opsForValue()).thenReturn(values);

        service.revoke(token("jti-1", NOW.plus(Duration.ofMinutes(12))));

        verify(values).set("auth:revoked-access:jti-1", "1", Duration.ofMinutes(13));
    }

    /** Verifiers accept a token for the clock skew after it expires, so logout must still revoke it. */
    @Test
    void revokeCoversATokenThatExpiredWithinTheClockSkew() {
        when(redis.opsForValue()).thenReturn(values);

        service.revoke(token("jti-1", NOW.minusSeconds(10)));

        verify(values).set("auth:revoked-access:jti-1", "1", Duration.ofMinutes(1));
    }

    /** The parser still accepts a token at exactly exp + skew. */
    @Test
    void revokeCoversATokenAtTheLastInstantItIsAccepted() {
        when(redis.opsForValue()).thenReturn(values);

        service.revoke(token("jti-1", NOW.minus(JwtTokenProvider.CLOCK_SKEW)));

        verify(values).set("auth:revoked-access:jti-1", "1", Duration.ofMinutes(1));
    }

    @Test
    void revokeSkipsATokenNoVerifierAcceptsAnyMore() {
        service.revoke(token("jti-1", NOW.minus(JwtTokenProvider.CLOCK_SKEW).minusMillis(1)));

        verify(redis, never()).opsForValue();
    }

    @Test
    void revokeSurvivesRedisBeingDownAndCountsIt() {
        when(redis.opsForValue()).thenReturn(values);
        doThrow(new RedisConnectionFailureException("down")).when(values).set(anyString(), anyString(), any(Duration.class));

        service.revoke(token("jti-1", NOW.plusSeconds(600)));

        assertThat(meters.counter("certping.auth.revocation.redis.failures", "operation", "revoke").count()).isEqualTo(1);
    }

    @Test
    void isRevokedReadsTheSharedKey() {
        when(redis.hasKey("auth:revoked-access:jti-1")).thenReturn(true);
        when(redis.hasKey("auth:revoked-access:jti-2")).thenReturn(false);

        assertThat(service.isRevoked("jti-1")).isTrue();
        assertThat(service.isRevoked("jti-2")).isFalse();
        assertThat(service.isRevoked(null)).isFalse();
    }

    /** Fails open by decision: a Redis outage must not stop every authenticated request. */
    @Test
    void isRevokedFailsOpenWhenRedisIsDownAndCountsIt() {
        when(redis.hasKey(eq("auth:revoked-access:jti-1"))).thenThrow(new RedisConnectionFailureException("down"));

        assertThat(service.isRevoked("jti-1")).isFalse();
        assertThat(meters.counter("certping.auth.revocation.redis.failures", "operation", "check").count()).isEqualTo(1);
    }
    /**
     * While Redis is down every call would wait out the client timeout (2s), holding a request thread
     * each time. After one failure the check is skipped for a few seconds, then Redis is tried again.
     */
    @Test
    void afterAFailureChecksSkipRedisForAWhileThenRetry() {
        MutableClock clock = new MutableClock(NOW);
        AccessTokenBlacklistService breaking = new AccessTokenBlacklistService(redis, meters, clock);
        when(redis.hasKey("auth:revoked-access:jti-1")).thenThrow(new RedisConnectionFailureException("down"));

        assertThat(breaking.isRevoked("jti-1")).isFalse();
        assertThat(breaking.isRevoked("jti-1")).isFalse();
        verify(redis, org.mockito.Mockito.times(1)).hasKey("auth:revoked-access:jti-1");

        clock.advance(Duration.ofSeconds(6));
        assertThat(breaking.isRevoked("jti-1")).isFalse();
        verify(redis, org.mockito.Mockito.times(2)).hasKey("auth:revoked-access:jti-1");
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
