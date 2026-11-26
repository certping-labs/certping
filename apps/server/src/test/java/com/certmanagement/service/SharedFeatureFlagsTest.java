// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Clock;

import static com.certmanagement.config.CacheConfig.FEATURE_FLAGS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A committed flag change bumps the shared version, and every pod drops its cached decisions when it moves. */
class SharedFeatureFlagsTest {

    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final CacheManager cacheManager = mock(CacheManager.class);
    private final Cache decisions = mock(Cache.class);
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private SharedFeatureFlags shared;

    @BeforeEach
    void setUp() {
        when(redis.opsForValue()).thenReturn(values);
        when(cacheManager.getCache(FEATURE_FLAGS)).thenReturn(decisions);
        shared = new SharedFeatureFlags(redis, cacheManager, meters, Clock.systemUTC());
    }

    @Test
    void aChangeBumpsTheSharedVersion() {
        shared.onChanged(new FeatureFlagsChangedEvent());

        verify(values).increment(SharedFeatureFlags.VERSION_KEY);
    }

    @Test
    void theFirstPollOnlyRecordsTheVersionAndAMovedVersionDropsTheDecisions() {
        when(values.get(SharedFeatureFlags.VERSION_KEY)).thenReturn("1");
        shared.pollForChanges();
        shared.pollForChanges();
        verify(decisions, never()).clear();

        when(values.get(SharedFeatureFlags.VERSION_KEY)).thenReturn("2");
        shared.pollForChanges();
        verify(decisions).clear();
    }

    @Test
    void anUnreachableRedisIsCountedAndNeverThrown() {
        when(values.increment(SharedFeatureFlags.VERSION_KEY))
                .thenThrow(new RedisConnectionFailureException("down"));
        when(values.get(SharedFeatureFlags.VERSION_KEY)).thenThrow(new RedisConnectionFailureException("down"));

        assertThatCode(() -> shared.onChanged(new FeatureFlagsChangedEvent())).doesNotThrowAnyException();
        assertThatCode(shared::pollForChanges).doesNotThrowAnyException();

        assertThat(meters.get("certping.feature_flags.shared.failures").tag("operation", "announce").counter()
                .count()).isEqualTo(1.0);
        assertThat(meters.get("certping.feature_flags.shared.failures").tag("operation", "poll").counter()
                .count()).isEqualTo(1.0);
        verify(decisions, never()).clear();
    }
}
