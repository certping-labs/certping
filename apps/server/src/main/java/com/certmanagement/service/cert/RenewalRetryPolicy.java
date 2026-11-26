// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.enums.RenewalStatus;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/** Defines when a renewal schedule comes back to the scheduler queue after a failure or a hold. */
public final class RenewalRetryPolicy {

    /** How often a schedule held by a feature switch is checked again. */
    static final Duration HOLD_RECHECK = Duration.ofMinutes(15);

    /**
     * The delay before the next try after the first, second, ... failure in a row; the last one repeats. A permanent
     * cause (a revoked DNS credential, say) settles at one try a day, which the customer may fix meanwhile.
     */
    static final List<Duration> FAILURE_DELAYS = List.of(
            Duration.ofMinutes(15), Duration.ofHours(1), Duration.ofHours(4), Duration.ofHours(12), Duration.ofHours(24));

    /** Upward jitter on a failure delay, so schedules that failed together do not all come back together. */
    static final int JITTER_PERCENT = 10;

    private RenewalRetryPolicy() {
    }

    /** When a schedule held by a feature switch is checked again. */
    public static OffsetDateTime holdRecheckAt() {
        return OffsetDateTime.now(ZoneOffset.UTC).plus(HOLD_RECHECK);
    }

    /**
     * Records a failed renewal attempt on {@code schedule}: one more failure in a row, {@code FAILED} unless a feature
     * switch holds the schedule (its hold status is what turns it back on), and the next try after the delay for
     * that many failures.
     */
    public static void recordFailure(RenewalScheduleEntity schedule) {
        int failures = schedule.getConsecutiveFailures() == null ? 1 : schedule.getConsecutiveFailures() + 1;
        schedule.setConsecutiveFailures(failures);
        if (!schedule.heldByFeatureSwitch()) {
            schedule.setLastRenewalStatus(RenewalStatus.FAILED.name());
        }
        schedule.setNextAttemptAt(OffsetDateTime.now(ZoneOffset.UTC).plus(delayAfter(failures)));
    }

    /** The delay before the next try after {@code consecutiveFailures} failures in a row, jitter included. */
    static Duration delayAfter(int consecutiveFailures) {
        Duration base = FAILURE_DELAYS.get(Math.min(Math.max(consecutiveFailures, 1), FAILURE_DELAYS.size()) - 1);
        long maxExtraSeconds = base.toSeconds() * JITTER_PERCENT / 100;
        return base.plusSeconds(ThreadLocalRandom.current().nextLong(maxExtraSeconds + 1));
    }
}
