// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * When a placed order is checked again and when it is given up: each interval but the last is used for four times
 * its own length after the order was placed, the last one from then on.
 */
public record CaOrderPolling(List<Duration> intervals, Duration deadline) {

    private static final int STEP_LENGTH_IN_INTERVALS = 4;

    public CaOrderPolling {
        if (intervals == null || intervals.isEmpty() || intervals.stream().anyMatch(i -> i == null || i.isNegative() || i.isZero())) {
            throw new IllegalArgumentException("intervals must hold at least one positive duration");
        }
        if (deadline == null || deadline.isNegative() || deadline.isZero()) {
            throw new IllegalArgumentException("deadline must be positive");
        }
        intervals = List.copyOf(intervals);
    }

    public Duration nextDelay(Instant orderPlacedAt, Instant now) {
        Duration elapsed = orderPlacedAt == null ? Duration.ZERO : Duration.between(orderPlacedAt, now);
        Duration stepEnd = Duration.ZERO;
        for (int i = 0; i < intervals.size() - 1; i++) {
            stepEnd = stepEnd.plus(intervals.get(i).multipliedBy(STEP_LENGTH_IN_INTERVALS));
            if (elapsed.compareTo(stepEnd) < 0) {
                return intervals.get(i);
            }
        }
        return intervals.get(intervals.size() - 1);
    }

    public boolean pastDeadline(Instant orderPlacedAt, Instant now) {
        return orderPlacedAt != null && now.isAfter(orderPlacedAt.plus(deadline));
    }
}
