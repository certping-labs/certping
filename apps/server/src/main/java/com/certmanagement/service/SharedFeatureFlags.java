// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.service.scheduler.RegisteredJob;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.certmanagement.config.CacheConfig.FEATURE_FLAGS;

/**
 * Takes flag changes beyond this pod, through the Redis every service shares.
 *
 * <p>Each pod caches flag decisions (CacheConfig). A committed change bumps {@link #VERSION_KEY};
 * every pod polls it and drops its decisions when it moves, so a flip applies everywhere within
 * {@link #POLL_SECONDS} seconds instead of the cache's TTL, which stays as the bound while Redis
 * is unreachable. Polling rather than pub/sub keeps Redis out of startup.
 *
 * <p>Nothing here throws: a flag write must not fail after its commit because Redis is down.
 * Failures are counted and logged once a minute.
 */
@Slf4j
@Component
public class SharedFeatureFlags {

    static final String VERSION_KEY = "feature-flags:version";
    static final long POLL_SECONDS = 2;

    private static final Duration WARN_EVERY = Duration.ofMinutes(1);

    private final StringRedisTemplate redis;
    private final CacheManager cacheManager;
    private final Clock clock;
    private final MeterRegistry meters;
    private final AtomicReference<String> seenVersion = new AtomicReference<>();
    private final AtomicReference<Instant> lastWarning = new AtomicReference<>(Instant.EPOCH);

    @Autowired
    public SharedFeatureFlags(StringRedisTemplate redis, CacheManager cacheManager, MeterRegistry meters) {
        this(redis, cacheManager, meters, Clock.systemUTC());
    }

    SharedFeatureFlags(StringRedisTemplate redis, CacheManager cacheManager, MeterRegistry meters, Clock clock) {
        this.redis = redis;
        this.cacheManager = cacheManager;
        this.meters = meters;
        this.clock = clock;
    }

    @TransactionalEventListener(fallbackExecution = true)
    public void onChanged(FeatureFlagsChangedEvent event) {
        try {
            redis.opsForValue().increment(VERSION_KEY);
        } catch (RuntimeException e) {
            failed("announce", e);
        }
    }

    @RegisteredJob("feature-flag-shared-sync")
    @Scheduled(fixedDelay = POLL_SECONDS, initialDelay = POLL_SECONDS, timeUnit = TimeUnit.SECONDS)
    public void pollForChanges() {
        String version;
        try {
            version = redis.opsForValue().get(VERSION_KEY);
        } catch (RuntimeException e) {
            failed("poll", e);
            return;
        }
        String previous = seenVersion.getAndSet(version);
        if (previous != null && !Objects.equals(previous, version)) {
            Cache decisions = cacheManager.getCache(FEATURE_FLAGS);
            if (decisions != null) {
                decisions.clear();
            }
            log.info("[FEATURE_FLAGS_CHANGED] version={}; cached decisions dropped", version);
        }
    }

    private void failed(String operation, RuntimeException e) {
        Counter.builder("certping.feature_flags.shared.failures")
                .description("Failures carrying flag changes through Redis; pods fall back to the cache TTL")
                .tag("operation", operation)
                .register(meters)
                .increment();
        Instant now = clock.instant();
        Instant last = lastWarning.get();
        if (now.isAfter(last.plus(WARN_EVERY)) && lastWarning.compareAndSet(last, now)) {
            log.warn("[FEATURE_FLAGS_SHARED_FAILED] operation={} error={}: {}",
                    operation, e.getClass().getSimpleName(), e.getMessage());
        }
    }
}
