// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

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
import java.util.concurrent.atomic.AtomicReference;

/**
 * Caps certificate exports per user: {@value #MAX_EXPORTS_PER_WINDOW} per fixed one-hour window,
 * counted in the Redis every pod shares, so the cap holds across replicas.
 *
 * <p>Fixed windows, accepted on purpose: the counter resets on the hour, so a user can make up to
 * twice the limit across a window boundary (the end of one window plus the start of the next). The
 * cap exists to bound bulk extraction, which that does not change materially; a sliding window would
 * cost a sorted set per user.
 *
 * <p>When Redis is unreachable the outcome depends on what leaves the platform. Formats carrying the
 * private key ({@link CertExportFormat#includesPrivateKey()}) fail CLOSED: the attempt is refused,
 * because the limiter is the only bound on how fast keys can be pulled out. Certificate-only formats
 * fail OPEN (the endpoint still requires {@code certificate:read}, org scoping and the feature flag),
 * the same trade-off {@link com.certmanagement.service.SharedFeatureFlags} makes. Either way the
 * failure is counted on {@value #FAILURE_METER} (tagged {@code mode=open|closed}) and logged at most
 * once a minute.
 */
@Slf4j
@Component
public class CertExportRateLimiter {

    static final int MAX_EXPORTS_PER_WINDOW = 30;
    static final Duration WINDOW = Duration.ofHours(1);
    static final String KEY_PREFIX = "cert-export:rate:";
    static final String FAILURE_METER = "certping.cert_export.rate_limit.failures";

    /** INCR and the first EXPIRE in one step, so a crash between them cannot leave a key without a TTL. */
    private static final RedisScript<Long> INCREMENT_WITH_TTL = RedisScript.of("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
            return count
            """, Long.class);
    private static final Duration WARN_EVERY = Duration.ofMinutes(1);

    private final StringRedisTemplate redis;
    private final MeterRegistry meters;
    private final Clock clock;
    private final AtomicReference<Instant> lastWarning = new AtomicReference<>(Instant.EPOCH);

    public CertExportRateLimiter(StringRedisTemplate redis, MeterRegistry meters, Clock clock) {
        this.redis = redis;
        this.meters = meters;
        this.clock = clock;
    }

    /**
     * Counts one export attempt by {@code userId} in {@code format}.
     *
     * @return {@link CertExportRateLimitDecision.Allowed}, {@link CertExportRateLimitDecision.Limited}
     *         with the seconds until the window resets, or
     *         {@link CertExportRateLimitDecision.LimiterUnavailable} for a private-key format while
     *         Redis is unreachable
     */
    public CertExportRateLimitDecision tryAcquire(Integer userId, CertExportFormat format) {
        long windowSeconds = WINDOW.toSeconds();
        long nowSeconds = clock.instant().getEpochSecond();
        long windowIndex = nowSeconds / windowSeconds;
        String key = KEY_PREFIX + userId + ":" + windowIndex;
        Long count;
        try {
            // TTL a little past the window so a slow clock on another pod still finds the key.
            count = redis.execute(INCREMENT_WITH_TTL, List.of(key), String.valueOf(windowSeconds + 60));
        } catch (RuntimeException e) {
            return decideWithoutRedis(format, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        if (count == null) {
            return decideWithoutRedis(format, "script returned no count");
        }
        if (count <= MAX_EXPORTS_PER_WINDOW) {
            return CertExportRateLimitDecision.ALLOWED;
        }
        long secondsUntilReset = (windowIndex + 1) * windowSeconds - nowSeconds;
        // The script's own count tells exactly one attempt per window that it was the first over.
        return new CertExportRateLimitDecision.Limited(Math.max(1, secondsUntilReset),
                count == MAX_EXPORTS_PER_WINDOW + 1);
    }

    private CertExportRateLimitDecision decideWithoutRedis(CertExportFormat format, String cause) {
        boolean failClosed = format.includesPrivateKey();
        Counter.builder(FAILURE_METER)
                .description("Export rate-limit checks that could not reach Redis; "
                        + "mode=closed refused the attempt, mode=open allowed it")
                .tag("mode", failClosed ? "closed" : "open")
                .register(meters)
                .increment();
        Instant now = clock.instant();
        Instant last = lastWarning.get();
        if (now.isAfter(last.plus(WARN_EVERY)) && lastWarning.compareAndSet(last, now)) {
            log.warn("[CERT_EXPORT_RATE_LIMIT_UNAVAILABLE] refusing private-key exports and allowing "
                    + "certificate-only exports without a limit: {}", cause);
        }
        return failClosed ? new CertExportRateLimitDecision.LimiterUnavailable()
                : CertExportRateLimitDecision.ALLOWED;
    }
}
