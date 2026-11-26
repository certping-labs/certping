// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Runs the limiter's Lua script against a real Redis: the count, the TTL and the refusal. */
@Testcontainers(disabledWithoutDocker = true)
class CertExportRateLimiterRedisTest {

    /** 2026-10-06T12:15:00Z: 45 minutes before the hourly window resets. */
    private static final Instant NOW = Instant.parse("2026-10-06T12:15:00Z");
    private static final String KEY = "cert-export:rate:7:" + NOW.getEpochSecond() / 3600;
    private static final String OTHER_USER_KEY = "cert-export:rate:8:" + NOW.getEpochSecond() / 3600;

    @Container
    private static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redis;

    private CertExportRateLimiter limiter;

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379)));
        connectionFactory.afterPropertiesSet();
        connectionFactory.start();
        redis = new StringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        connectionFactory.destroy();
    }

    @BeforeEach
    void setUp() {
        redis.delete(List.of(KEY, OTHER_USER_KEY));
        limiter = new CertExportRateLimiter(redis, new SimpleMeterRegistry(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void allowsThirty_thenRefusesWithRetryAfter_reportingOnlyTheFirstRefusalAsSuch() {
        for (int attempt = 1; attempt <= CertExportRateLimiter.MAX_EXPORTS_PER_WINDOW; attempt++) {
            assertThat(limiter.tryAcquire(7, CertExportFormat.PKCS12)).isEqualTo(CertExportRateLimitDecision.ALLOWED);
        }

        assertThat(limiter.tryAcquire(7, CertExportFormat.PKCS12))
                .isEqualTo(new CertExportRateLimitDecision.Limited(45 * 60, true));
        assertThat(limiter.tryAcquire(7, CertExportFormat.FULLCHAIN_PEM))
                .isEqualTo(new CertExportRateLimitDecision.Limited(45 * 60, false));
        assertThat(redis.opsForValue().get(KEY)).isEqualTo("32");
        assertThat(limiter.tryAcquire(8, CertExportFormat.PKCS12)).isEqualTo(CertExportRateLimitDecision.ALLOWED);
    }

    @Test
    void setsTheTtlOnTheFirstHitOnly() {
        limiter.tryAcquire(7, CertExportFormat.FULLCHAIN_PEM);

        Long ttl = redis.getExpire(KEY);
        assertThat(ttl).isBetween(3600L, 3660L);

        redis.expire(KEY, Duration.ofSeconds(100));
        limiter.tryAcquire(7, CertExportFormat.FULLCHAIN_PEM);

        assertThat(redis.getExpire(KEY)).isBetween(1L, 100L);
        assertThat(redis.opsForValue().get(KEY)).isEqualTo("2");
    }
}
