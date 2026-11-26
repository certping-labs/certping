// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.security.AccessToken;
import com.certmanagement.security.JwtTokenProvider;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.redis.autoconfigure.DataRedisProperties;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Revoked access tokens, in the Redis every service shares, so a logout takes effect everywhere
 * without any service calling the server. Each entry lives as long as the token it revokes plus a
 * minute, then disappears on its own. Refresh-token revocation stays in Postgres: only the server
 * ever handles refresh tokens.
 *
 * <p>Both directions fail open. An unreachable Redis must not stop every authenticated request, so
 * a revoked token can work during an outage for at most its remaining lifetime. Failures are
 * counted for alerting. After a failed check the next few seconds skip Redis entirely: otherwise
 * every request waits out the client timeout and an outage exhausts the request threads.
 */
@Service
@Slf4j
public class AccessTokenBlacklistService {

    /** Key format shared with every verifier; see docs/operations.md#jwt-signing-keys. */
    public static final String KEY_PREFIX = "auth:revoked-access:";
    /** An access token kept working past its user's tokens_valid_after (see {@link #exempt}). */
    static final String EXEMPT_PREFIX = "auth:exempt-access:";

    // Outlives every verifier's acceptance of the token, which ends CLOCK_SKEW after it expires.
    private static final Duration GRACE = Duration.ofMinutes(1);
    private static final Duration WARN_EVERY = Duration.ofMinutes(1);
    private static final Duration SKIP_AFTER_FAILURE = Duration.ofSeconds(5);

    private final StringRedisTemplate redis;
    private final Clock clock;
    private final Counter revokeFailures;
    private final Counter checkFailures;
    private final AtomicReference<Instant> lastCheckWarning = new AtomicReference<>(Instant.EPOCH);
    private final AtomicReference<Instant> skipChecksUntil = new AtomicReference<>(Instant.EPOCH);

    @Autowired
    public AccessTokenBlacklistService(StringRedisTemplate redis, MeterRegistry meters, DataRedisProperties redisProperties) {
        this(redis, meters, Clock.systemUTC());
        requireHost(redisProperties.getHost());
    }

    AccessTokenBlacklistService(StringRedisTemplate redis, MeterRegistry meters, Clock clock) {
        this.redis = redis;
        this.clock = clock;
        this.revokeFailures = failures(meters, "revoke");
        this.checkFailures = failures(meters, "check");
    }

    public void revoke(AccessToken token) {
        if (token.jti() == null) {
            return;
        }
        Instant now = clock.instant();
        if (now.isAfter(token.expiresAt().plus(JwtTokenProvider.CLOCK_SKEW))) {
            return;
        }
        Duration remaining = Duration.between(now, token.expiresAt());
        if (remaining.isNegative()) {
            remaining = Duration.ZERO;
        }
        try {
            redis.opsForValue().set(KEY_PREFIX + token.jti(), "1", remaining.plus(GRACE));
        } catch (DataAccessException e) {
            revokeFailures.increment();
            log.error("Access token revocation not recorded (Redis unavailable); jti={} stays valid until it expires in {}s",
                    token.jti(), remaining.toSeconds());
        }
    }

    /**
     * Keeps one access token working past its user's {@code tokens_valid_after}: the token that just
     * changed the password, so the session that made the change continues while every other one ends.
     * Lives as long as the token. A Redis error loses the exemption, which only signs that session out.
     */
    public void exempt(AccessToken token) {
        if (token == null || token.jti() == null) {
            return;
        }
        Duration remaining = Duration.between(clock.instant(), token.expiresAt());
        if (remaining.isNegative() || remaining.isZero()) {
            return;
        }
        try {
            redis.opsForValue().set(EXEMPT_PREFIX + token.jti(), "1", remaining.plus(GRACE));
        } catch (DataAccessException e) {
            revokeFailures.increment();
            log.warn("Access token exemption not recorded (Redis unavailable); jti={} is refused like the others",
                    token.jti());
        }
    }

    /** Whether {@link #exempt} kept this token. False on any Redis error: the refusal stands. */
    public boolean isExempt(String jti) {
        if (jti == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(redis.hasKey(EXEMPT_PREFIX + jti));
        } catch (DataAccessException e) {
            checkFailures.increment();
            return false;
        }
    }

    public boolean isRevoked(String jti) {
        if (jti == null || clock.instant().isBefore(skipChecksUntil.get())) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(redis.hasKey(KEY_PREFIX + jti));
        } catch (DataAccessException e) {
            skipChecksUntil.set(clock.instant().plus(SKIP_AFTER_FAILURE));
            checkFailures.increment();
            warnAtMostOncePerMinute(e);
            return false;
        }
    }

    // One line per minute during an outage, not one per request; the counter carries the volume.
    private void warnAtMostOncePerMinute(DataAccessException e) {
        Instant now = clock.instant();
        Instant last = lastCheckWarning.get();
        if (now.isAfter(last.plus(WARN_EVERY)) && lastCheckWarning.compareAndSet(last, now)) {
            log.warn("Access token revocation check skipped (Redis unavailable: {}); allowing requests until it recovers",
                    e.getClass().getSimpleName());
        }
    }

    // A profile may give REDIS_HOST no default, and the binder keeps an unresolved placeholder as text.
    // Starting anyway would fail open on every check, so a logged-out token would keep working.
    private static void requireHost(String host) {
        if (host == null || host.isBlank() || host.contains("${")) {
            throw new IllegalStateException("spring.data.redis.host (REDIS_HOST) is required: revoked access tokens live in Redis");
        }
    }

    private static Counter failures(MeterRegistry meters, String operation) {
        return Counter.builder("certping.auth.revocation.redis.failures")
                .description("Redis errors while revoking or checking access tokens; checks fail open")
                .tag("operation", operation)
                .register(meters);
    }
}
