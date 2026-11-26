// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * How much one reconciler sweep may do: at most {@code maxOrganizations} reconciled organizations and
 * {@code maxDuration} of wall-clock time. What is left waits for the next run. Not thread-safe; one
 * sweep owns one budget.
 */
public final class SweepBudget {

    private final long deadlineNanos;
    private final LongSupplier nanoClock;
    private int remainingOrganizations;

    SweepBudget(int maxOrganizations, Duration maxDuration, LongSupplier nanoClock) {
        this.nanoClock = nanoClock;
        this.deadlineNanos = nanoClock.getAsLong() + maxDuration.toNanos();
        this.remainingOrganizations = maxOrganizations;
    }

    public static SweepBudget of(int maxOrganizations, Duration maxDuration) {
        return new SweepBudget(maxOrganizations, maxDuration, System::nanoTime);
    }

    boolean isExhausted() {
        return remainingOrganizations <= 0 || nanoClock.getAsLong() - deadlineNanos >= 0;
    }

    void consume() {
        remainingOrganizations--;
    }
}
