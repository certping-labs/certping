// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Fixed-window counters in the Redis every pod shares: at most {@code limit} calls per key per window.
 * Like {@link com.certmanagement.service.cert.export.CertExportRateLimiter}, a caller can make up to twice
 * the limit across a window boundary; that bounds a brute force as well and costs one key per window.
 *
 * <p>Fails open: an unreachable Redis allows the call (counted on {@value #FAILURE_METER}, logged at most
 * once a minute). The limits this backs are abuse brakes in front of checks that hold on their own
 * (password lockout, agent token checks), not the only control.
 */
@Slf4j
@Component
public class FixedWindowRateLimiter {

    static final String FAILURE_METER = "certping.rate_limit.redis.failures";

    /** INCR and the first EXPIRE in one step, so a crash between them cannot leave a key without a TTL. */
    private static final RedisScript<Long> INCREMENT_WITH_TTL = RedisScript.of("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
            return count
            """, Long.class);
    private static final Duration WARN_EVERY = Duration.ofMinutes(1);

    private final StringRedisTemplate redis;
    private final Clock clock;
    private final Counter failures;
    private final AtomicReference<Instant> lastWarning = new AtomicReference<>(Instant.EPOCH);

    public FixedWindowRateLimiter(StringRedisTemplate redis, MeterRegistry meters, Clock clock) {
        this.redis = redis;
        this.clock = clock;
        this.failures = Counter.builder(FAILURE_METER)
                .description("Rate-limit checks that could not reach Redis and were allowed")
                .register(meters);
    }

    /**
     * Counts one call for {@code key}.
     *
     * @return empty when allowed, else the seconds until the window resets (at least 1)
     */
    public OptionalLong tryAcquire(String key, int limit, Duration window) {
        long windowSeconds = Math.max(1, window.toSeconds());
        long nowSeconds = clock.instant().getEpochSecond();
        long windowIndex = nowSeconds / windowSeconds;
        Long count;
        try {
            // TTL a little past the window so a pod with a slow clock still finds the key.
            count = redis.execute(INCREMENT_WITH_TTL, List.of(key + ":" + windowIndex),
                    String.valueOf(windowSeconds + 60));
        } catch (RuntimeException e) {
            unavailable(e.getClass().getSimpleName());
            return OptionalLong.empty();
        }
        if (count == null) {
            unavailable("script returned no count");
            return OptionalLong.empty();
        }
        if (count <= limit) {
            return OptionalLong.empty();
        }
        return OptionalLong.of(Math.max(1, (windowIndex + 1) * windowSeconds - nowSeconds));
    }

    private void unavailable(String cause) {
        failures.increment();
        Instant now = clock.instant();
        Instant last = lastWarning.get();
        if (now.isAfter(last.plus(WARN_EVERY)) && lastWarning.compareAndSet(last, now)) {
            log.warn("[RATE_LIMIT_UNAVAILABLE] allowing calls without a limit while Redis is unreachable: {}", cause);
        }
    }
}
