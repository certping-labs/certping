// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import java.time.Instant;

/** What the last completed check of one component says, and how many checks in a row failed. */
record ComponentReading(ComponentStatus status, int consecutiveFailures, Instant checkedAt) {

    static final int FAILURES_TO_LEAVE_OPERATIONAL = 2;

    static ComponentReading first(PublicComponent component, boolean up, Instant checkedAt) {
        return up
                ? new ComponentReading(ComponentStatus.OPERATIONAL, 0, checkedAt)
                : new ComponentReading(component.failureStatus(), 1, checkedAt);
    }

    ComponentReading next(PublicComponent component, boolean up, Instant checkedAt) {
        if (up) {
            return new ComponentReading(ComponentStatus.OPERATIONAL, 0, checkedAt);
        }
        int failures = consecutiveFailures + 1;
        ComponentStatus next = failures >= FAILURES_TO_LEAVE_OPERATIONAL ? component.failureStatus() : status;
        return new ComponentReading(next, failures, checkedAt);
    }
}
