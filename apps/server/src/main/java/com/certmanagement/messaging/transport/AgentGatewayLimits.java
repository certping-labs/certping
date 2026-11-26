// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import com.certmanagement.service.FixedWindowRateLimiter;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per agent token limits on the gateway, so one token (a leaked one, or a misbehaving agent) cannot tie up
 * request threads, database connections or the queue: open long-polls per token on this server, requests
 * per token per minute (shared across pods in Redis, failing open), and messages one organization may have
 * waiting. Each refusal is a 429. Tokens are keyed by a hash, never the token itself.
 */
@Component
public class AgentGatewayLimits {

    static final String RATE_KEY_PREFIX = "agent-gateway-rate:";
    static final String SETTLE_RATE_KEY_PREFIX = "agent-gateway-rate-settle:";

    private final TransportProperties properties;
    private final FixedWindowRateLimiter rateLimiter;
    private final PostgresMessageQueue queue;
    private final ConcurrentHashMap<String, AtomicInteger> openPolls = new ConcurrentHashMap<>();

    public AgentGatewayLimits(TransportProperties properties, FixedWindowRateLimiter rateLimiter,
                              PostgresMessageQueue queue) {
        this.properties = properties;
        this.rateLimiter = rateLimiter;
        this.queue = queue;
    }

    /** A stable, non-reversible key for a token. */
    public static String keyOf(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** What a gateway call is, for the per token rate limits. */
    public enum RequestKind {
        /** A receive (long poll). The kind an idle or looping agent repeats, so the tight limit. */
        POLL,
        /** Complete, abandon, dead-letter, renew-lock, send and whoami: work an agent does on messages. */
        SETTLE
    }

    /**
     * Counts one request of the token: a receive against
     * {@link TransportProperties#getMaxRequestsPerTokenPerMinute()}, anything else against the much higher
     * {@link TransportProperties#getMaxSettleRequestsPerTokenPerMinute()}, so a deployment burst of complete and
     * send calls is not refused. Over it: 429 with Retry-After in seconds.
     */
    public void countRequest(String tokenKey, RequestKind kind) {
        boolean poll = kind == RequestKind.POLL;
        String key = (poll ? RATE_KEY_PREFIX : SETTLE_RATE_KEY_PREFIX) + tokenKey;
        int limit = poll ? properties.getMaxRequestsPerTokenPerMinute()
                : properties.getMaxSettleRequestsPerTokenPerMinute();
        rateLimiter.tryAcquire(key, limit, Duration.ofMinutes(1)).ifPresent(retryAfter -> {
            throw tooManyRequests("too many " + (poll ? "receive" : "settle and send")
                    + " requests for this agent token; retry in " + retryAfter + "s", retryAfter);
        });
    }

    /** A 429 that carries {@code Retry-After: seconds} (at least 1). */
    public static ResponseStatusException tooManyRequests(String reason, long retryAfterSeconds) {
        long seconds = Math.max(1, retryAfterSeconds);
        return new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, reason) {
            @Override
            public org.springframework.http.HttpHeaders getHeaders() {
                org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
                headers.set(org.springframework.http.HttpHeaders.RETRY_AFTER, String.valueOf(seconds));
                return headers;
            }
        };
    }

    /**
     * Takes one long-poll slot of the token, or 429 when it already holds
     * {@link TransportProperties#getMaxConcurrentPollsPerToken()}. Close the returned slot when the poll ends.
     */
    public PollSlot openPoll(String tokenKey) {
        AtomicInteger open = openPolls.computeIfAbsent(tokenKey, key -> new AtomicInteger());
        if (open.incrementAndGet() > properties.getMaxConcurrentPollsPerToken()) {
            release(tokenKey, open);
            throw tooManyRequests("too many open receive calls for this agent token", 1);
        }
        return () -> release(tokenKey, open);
    }

    private void release(String tokenKey, AtomicInteger open) {
        if (open.decrementAndGet() <= 0) {
            // Drop idle entries so the map holds only tokens that are polling right now.
            openPolls.remove(tokenKey, open);
        }
    }

    /** 429 when the organization already has the most messages waiting on {@code channel}. */
    public void checkQueueRoom(String channel, Long organizationId) {
        int cap = properties.getMaxWaitingMessagesPerOrganization();
        if (queue.countWaiting(channel, organizationId, cap) >= cap) {
            throw tooManyRequests("too many messages waiting for this organization; retry later", 5);
        }
    }

    int openPolls(String tokenKey) {
        AtomicInteger open = openPolls.get(tokenKey);
        return open == null ? 0 : open.get();
    }

    /** An open long-poll slot. */
    @FunctionalInterface
    public interface PollSlot extends AutoCloseable {
        @Override
        void close();
    }
}
