// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import java.time.Duration;
import java.time.OffsetDateTime;

/**
 * When a certificate becomes eligible for renewal.
 *
 * <p>A fixed window ("30 days before expiry") was right when every certificate lived a year. It is
 * wrong for the 90-day and 64-day lifetimes public CAs are moving to: 30 days before a 64-day
 * certificate expires is barely past its midpoint, so a renewal glitch leaves little time, while a
 * window longer than the lifetime makes the certificate eligible the moment it is issued. The rule
 * here is the one Let's Encrypt recommends, renewal at about two-thirds of the lifetime, applied as
 * a cap on the configured window: the eligible time is {@code validTo} minus the smaller of the
 * window and a third of the lifetime, never less than one day before expiry.
 */
public final class RenewalTiming {

    /** The window a schedule gets when nothing else is configured. */
    public static final int DEFAULT_WINDOW_DAYS = 30;

    private RenewalTiming() {
    }

    /**
     * The eligible time for a certificate valid from {@code validFrom} to {@code validTo} with a
     * configured {@code windowDays}. With no {@code validFrom} (a certificate whose start is unknown),
     * the configured window is used as it is.
     */
    public static OffsetDateTime eligibleAt(OffsetDateTime validFrom, OffsetDateTime validTo, Integer windowDays) {
        int window = windowDays == null || windowDays < 1 ? DEFAULT_WINDOW_DAYS : windowDays;
        if (validFrom == null || !validFrom.isBefore(validTo)) {
            return validTo.minusDays(window);
        }
        long lifetimeDays = Duration.between(validFrom, validTo).toDays();
        long third = Math.max(1, lifetimeDays / 3);
        return validTo.minusDays(Math.min(window, third));
    }
}
