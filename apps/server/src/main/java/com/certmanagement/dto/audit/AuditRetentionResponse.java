// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import java.time.Instant;

/**
 * The audit retention setting as the super admin's settings card shows it.
 *
 * @param months                   whole months audit events are kept
 * @param retentionDays            {@code months} in days, approximately (an average month), for display
 * @param minMonths                the shortest period allowed
 * @param maxMonths                the longest period allowed
 * @param effectiveFrom            when the retention run that applies this setting starts: the next scheduled run
 *                                 once the grace period has passed, never the moment of the save; {@code null}
 *                                 while the period is unconfirmed, when nothing is dropped at all
 * @param oldestRetainedMonth      the oldest month ({@code YYYY-MM}) that run keeps; every earlier month is
 *                                 dropped whole, so rows are kept up to one month longer than {@code months}
 * @param oldestStoredMonth        the oldest month ({@code YYYY-MM}) still stored now, or {@code null} when none;
 *                                 earlier than {@code oldestRetainedMonth} means that run deletes months
 * @param automaticDeletionEnabled whether the retention job may run here (its kill switch
 *                                 {@code AUDIT_RETENTION_PURGE} and environment switch are on)
 * @param updatedAt                when the setting last changed, or {@code null} when it never has
 * @param previousMonths           on a change, the period before it; {@code null} otherwise
 * @param confirmed                whether a super admin has confirmed the period; until then nothing is dropped
 * @param confirmedAt              when it was last confirmed, or {@code null}
 * @param deletionWouldStartAt     the {@code effectiveFrom} a first confirmation or a shortening saved now would
 *                                 get: the first scheduled run at or after now plus the grace period, from the
 *                                 configured schedule and grace; {@code null} while deletion is switched off
 *                                 ({@code deletionHeldBy} is {@code KILL_SWITCH})
 * @param deletionHeldBy           what holds every deletion whatever is saved: {@code KILL_SWITCH} (the job may not
 *                                 run here: its kill switch {@code AUDIT_RETENTION_PURGE} or its environment switch
 *                                 is off), or {@code null}. An unconfirmed period is {@code confirmed: false}, not a
 *                                 hold here
 */
public record AuditRetentionResponse(
        int months,
        long retentionDays,
        int minMonths,
        int maxMonths,
        Instant effectiveFrom,
        String oldestRetainedMonth,
        String oldestStoredMonth,
        boolean automaticDeletionEnabled,
        Instant updatedAt,
        Integer previousMonths,
        boolean confirmed,
        Instant confirmedAt,
        Instant deletionWouldStartAt,
        String deletionHeldBy) {
}
