// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class HeartbeatCadenceState {

    private static final long MIN_INTERVAL_MS = 60_000L;
    private static final long MAX_INTERVAL_MS = 3_600_000L;

    private final AtomicLong heartbeatIntervalMs;
    private final AtomicReference<Instant> lastPublishedAt = new AtomicReference<>(Instant.EPOCH);

    public HeartbeatCadenceState(AgentProperties properties) {
        long configured = properties.getHealth().getHeartbeatIntervalMs();
        this.heartbeatIntervalMs = new AtomicLong(sanitizeInterval(configured));
    }

    public long getHeartbeatIntervalMs() {
        return heartbeatIntervalMs.get();
    }

    public void updateFromMinutes(int minutes) {
        long intervalMs = sanitizeInterval(minutes * 60_000L);
        heartbeatIntervalMs.set(intervalMs);
    }

    public boolean shouldPublishNow() {
        Instant last = lastPublishedAt.get();
        long elapsedMs = Duration.between(last, Instant.now()).toMillis();
        return elapsedMs >= heartbeatIntervalMs.get();
    }

    public void markPublishedNow() {
        lastPublishedAt.set(Instant.now());
    }

    private long sanitizeInterval(long intervalMs) {
        if (intervalMs < MIN_INTERVAL_MS) {
            return MIN_INTERVAL_MS;
        }
        if (intervalMs > MAX_INTERVAL_MS) {
            return MAX_INTERVAL_MS;
        }
        return intervalMs;
    }
}
