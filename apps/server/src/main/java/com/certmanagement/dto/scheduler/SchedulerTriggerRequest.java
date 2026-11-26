// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.scheduler;

import lombok.Data;

/**
 * Request body for internal scheduler endpoints.
 *
 * <p>All fields are optional — defaults are applied in the service layer.</p>
 */
@Data
public class SchedulerTriggerRequest {

    /**
     * When true, the service runs the query and returns what it would do
     * without writing any DB changes or publishing any messages.
     * Useful for manual previews and testing.
     */
    private boolean dryRun = false;

    /**
     * Days before expiry threshold — used by trigger-expiry-alerts.
     * Ignored by mark-expired-certs and trigger-renewals (they use their own eligibility logic).
     */
    private int daysBeforeExpiry = 30;
}
