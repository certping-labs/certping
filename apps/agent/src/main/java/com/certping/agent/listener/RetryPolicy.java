// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.config.AgentProperties;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot of the scheduled-retry policy, built once at startup from
 * {@link AgentProperties.RetryProperties}. Shared by {@link ScheduledRetryService} (delay
 * computation) and the listener (give-up decision) so both reason about the same numbers.
 */
public record RetryPolicy(
        int maxScheduledRetries,
        Map<String, Integer> maxRetriesByReason,
        int absoluteMaxScheduledRetries,
        Duration hardCapNewOrder,
        Duration hardCapRenewal,
        Duration maxAttemptAgeNewOrder,
        Duration maxAttemptAgeRenewal,
        int jitterPercent,
        List<Duration> blindBackoff) {

    private static final Duration FALLBACK_BACKOFF = Duration.ofSeconds(30);

    public RetryPolicy {
        if (maxScheduledRetries < 1) {
            throw new IllegalArgumentException("maxScheduledRetries must be >= 1, was " + maxScheduledRetries);
        }
        if (absoluteMaxScheduledRetries < maxScheduledRetries) {
            throw new IllegalArgumentException("absoluteMaxScheduledRetries must be >= maxScheduledRetries, was "
                    + absoluteMaxScheduledRetries);
        }
        maxRetriesByReason = maxRetriesByReason == null ? Map.of() : Map.copyOf(maxRetriesByReason);
        if (jitterPercent < 0 || jitterPercent > 100) {
            throw new IllegalArgumentException("jitterPercent must be in [0,100], was " + jitterPercent);
        }
        blindBackoff = (blindBackoff == null || blindBackoff.isEmpty())
                ? List.of(FALLBACK_BACKOFF)
                : List.copyOf(blindBackoff);
    }

    public static RetryPolicy from(AgentProperties.RetryProperties p) {
        return new RetryPolicy(
                p.getMaxScheduledRetries(),
                p.getMaxRetriesByReason(),
                p.getAbsoluteMaxScheduledRetries(),
                p.getHardCapNewOrder(),
                p.getHardCapRenewal(),
                p.getMaxAttemptAgeNewOrder(),
                p.getMaxAttemptAgeRenewal(),
                p.getJitterPercent(),
                p.getBlindBackoff());
    }

    /**
     * Whether a message retried {@code totalRetries} times, {@code reasonRetries} of them for {@code reason}, may
     * not be retried for {@code reason} again.
     */
    public boolean exhausted(String reason, int totalRetries, int reasonRetries) {
        if (totalRetries >= absoluteMaxScheduledRetries) {
            return true;
        }
        Integer reasonCap = reason == null ? null : maxRetriesByReason.get(reason);
        if (reasonCap == null) {
            return totalRetries >= maxScheduledRetries;
        }
        return reasonCap >= 0 && reasonRetries >= reasonCap;
    }

    /** Renewals get the more generous cap — the existing cert is still valid while we wait. */
    public Duration hardCapFor(boolean renewal) {
        return renewal ? hardCapRenewal : hardCapNewOrder;
    }

    /** How long after its original enqueue time a message may still be retried. */
    public Duration maxAttemptAgeFor(boolean renewal) {
        return renewal ? maxAttemptAgeRenewal : maxAttemptAgeNewOrder;
    }

    /** Blind backoff step for the given (pre-increment) retry count, clamped to the curve. */
    public Duration blindBackoffFor(int retryCount) {
        int idx = Math.min(Math.max(retryCount, 0), blindBackoff.size() - 1);
        return blindBackoff.get(idx);
    }
}
