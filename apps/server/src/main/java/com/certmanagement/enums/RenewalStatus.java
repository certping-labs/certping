// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

/**
 * Values for {@code renewal_schedule.last_renewal_status}.
 *
 * <p>Stored as {@link #name()} (plain VARCHAR). {@code null} is also a valid state (schedule not yet
 * attempted, or reverted after a failed publish) — use {@code null} directly for that case.
 */
public enum RenewalStatus {
    IN_PROGRESS,
    SUCCESS,
    FAILED,
    /**
     * Held because {@code CERTIFICATE_RENEWAL} is off for the organization. Disabled by the feature
     * lifecycle (turned back on with the feature), or, when the renewal trigger found it due first,
     * still enabled with a {@code next_attempt_at} at which the trigger checks again.
     */
    FEATURE_HOLD,
    /**
     * Held because a CertPing DNS key the renewal needs has expired. Still enabled, with a {@code next_attempt_at}
     * at which the trigger checks again; renewing the key rearms it at once.
     */
    DNS_KEY_EXPIRED_HOLD
}
