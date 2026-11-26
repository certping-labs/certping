// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CertExportRateLimiterTest {

    /** 2026-10-06T12:15:00Z: 45 minutes before the hourly window resets. */
    private static final Instant NOW = Instant.parse("2026-10-06T12:15:00Z");
    private static final long WINDOW_INDEX = NOW.getEpochSecond() / 3600;

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final CertExportRateLimiter limiter =
            new CertExportRateLimiter(redis, meters, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    @SuppressWarnings("unchecked")
    void allowsUpToThirtyPerUserPerHour_keyedByUserAndWindow() {
        when(redis.execute(any(RedisScript.class), anyList(), any())).thenReturn(30L);

        assertThat(limiter.tryAcquire(7, CertExportFormat.PKCS12)).isEqualTo(CertExportRateLimitDecision.ALLOWED);
        verify(redis).execute(any(RedisScript.class),
                eq(List.of("cert-export:rate:7:" + WINDOW_INDEX)), eq("3660"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void refusesTheThirtyFirst_asTheFirstRefusal_withSecondsUntilTheWindowResets() {
        when(redis.execute(any(RedisScript.class), anyList(), any())).thenReturn(31L);

        assertThat(limiter.tryAcquire(7, CertExportFormat.FULLCHAIN_PEM))
                .isEqualTo(new CertExportRateLimitDecision.Limited(45 * 60, true));
    }

    @Test
    @SuppressWarnings("unchecked")
    void laterRefusalsInTheWindow_areNotTheFirst() {
        when(redis.execute(any(RedisScript.class), anyList(), any())).thenReturn(32L, 90L);

        assertThat(limiter.tryAcquire(7, CertExportFormat.FULLCHAIN_PEM))
                .isEqualTo(new CertExportRateLimitDecision.Limited(45 * 60, false));
        assertThat(limiter.tryAcquire(7, CertExportFormat.FULLCHAIN_PEM))
                .isEqualTo(new CertExportRateLimitDecision.Limited(45 * 60, false));
    }

    @ParameterizedTest
    @EnumSource(value = CertExportFormat.class, names = {"PRIVATE_KEY_PEM", "PKCS12"})
    @SuppressWarnings("unchecked")
    void privateKeyFormats_failClosedAndCountWhenRedisIsDown(CertExportFormat format) {
        when(redis.execute(any(RedisScript.class), anyList(), any()))
                .thenThrow(new RedisConnectionFailureException("down"));

        assertThat(limiter.tryAcquire(7, format)).isInstanceOf(CertExportRateLimitDecision.LimiterUnavailable.class);
        assertThat(meters.get(CertExportRateLimiter.FAILURE_METER).tag("mode", "closed").counter().count())
                .isEqualTo(1.0);
    }

    @ParameterizedTest
    @EnumSource(value = CertExportFormat.class, names = {"FULLCHAIN_PEM", "CERTIFICATE_PEM"})
    @SuppressWarnings("unchecked")
    void certificateOnlyFormats_failOpenAndCountWhenRedisIsDown(CertExportFormat format) {
        when(redis.execute(any(RedisScript.class), anyList(), any()))
                .thenThrow(new RedisConnectionFailureException("down"));

        assertThat(limiter.tryAcquire(7, format)).isEqualTo(CertExportRateLimitDecision.ALLOWED);
        assertThat(limiter.tryAcquire(7, format)).isEqualTo(CertExportRateLimitDecision.ALLOWED);
        assertThat(meters.get(CertExportRateLimiter.FAILURE_METER).tag("mode", "open").counter().count())
                .isEqualTo(2.0);
    }

    @Test
    @SuppressWarnings("unchecked")
    void aMissingCount_isTreatedAsRedisBeingUnavailable() {
        when(redis.execute(any(RedisScript.class), anyList(), any())).thenReturn(null);

        assertThat(limiter.tryAcquire(7, CertExportFormat.PKCS12))
                .isInstanceOf(CertExportRateLimitDecision.LimiterUnavailable.class);
        assertThat(limiter.tryAcquire(7, CertExportFormat.FULLCHAIN_PEM)).isEqualTo(CertExportRateLimitDecision.ALLOWED);
    }
}
