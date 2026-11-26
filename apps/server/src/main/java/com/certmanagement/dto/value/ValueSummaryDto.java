// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.value;

/**
 * What CertPing did for an organization over the last {@code days} days, and the manual work that saved.
 *
 * @param renewedBeforeExpiry renewals that completed before the replaced certificate's not_after
 * @param minutesSaved        manual work avoided, from the per-task {@code assumptions}
 * @param unmanagedDiscovered certificates discovery found (not MISSING) that CertPing does not manage
 *                            ({@code managed = false})
 * @param unmanagedExpiringSoon those of them that expire within 30 days and have not expired yet
 */
public record ValueSummaryDto(
        int days,
        String since,
        long issuances,
        long renewals,
        long scheduledRenewals,
        long automatedDeployments,
        long renewedBeforeExpiry,
        long minutesSaved,
        long unmanagedDiscovered,
        long unmanagedExpiringSoon,
        Assumptions assumptions) {

    public record Assumptions(int minutesPerRenewal, int minutesPerDeployment, int minutesPerIssuance) {
    }
}
