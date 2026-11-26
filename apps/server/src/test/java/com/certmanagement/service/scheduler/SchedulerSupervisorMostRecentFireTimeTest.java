// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class SchedulerSupervisorMostRecentFireTimeTest {

    @Test
    void dailyCron_afterFireTime_returnsSameDayFire() {
        OffsetDateTime now = OffsetDateTime.of(2026, 7, 20, 7, 30, 0, 0, ZoneOffset.UTC);
        OffsetDateTime last = SchedulerSupervisor.mostRecentFireTimeBefore("0 0 6 * * *", now);
        assertThat(last).isEqualTo(OffsetDateTime.of(2026, 7, 20, 6, 0, 0, 0, ZoneOffset.UTC));
    }

    @Test
    void dailyCron_beforeFireTime_returnsPreviousDayFire() {
        OffsetDateTime now = OffsetDateTime.of(2026, 7, 20, 5, 58, 0, 0, ZoneOffset.UTC);
        OffsetDateTime last = SchedulerSupervisor.mostRecentFireTimeBefore("0 0 6 * * *", now);
        assertThat(last).isEqualTo(OffsetDateTime.of(2026, 7, 19, 6, 0, 0, 0, ZoneOffset.UTC));
    }

    @Test
    void monthlyCron_afterFireTime_returnsFirstOfThisMonth() {
        OffsetDateTime now = OffsetDateTime.of(2026, 7, 3, 9, 0, 0, 0, ZoneOffset.UTC);
        OffsetDateTime last = SchedulerSupervisor.mostRecentFireTimeBefore("0 0 6 1 * *", now);
        assertThat(last).isEqualTo(OffsetDateTime.of(2026, 7, 1, 6, 0, 0, 0, ZoneOffset.UTC));
    }

    @Test
    void monthlyCron_beforeFireTime_returnsFirstOfPreviousMonth() {
        OffsetDateTime now = OffsetDateTime.of(2026, 7, 1, 5, 58, 0, 0, ZoneOffset.UTC);
        OffsetDateTime last = SchedulerSupervisor.mostRecentFireTimeBefore("0 0 6 1 * *", now);
        assertThat(last).isEqualTo(OffsetDateTime.of(2026, 6, 1, 6, 0, 0, 0, ZoneOffset.UTC));
    }

    @Test
    void everyMinuteCron_returnsMostRecentMinute() {
        OffsetDateTime now = OffsetDateTime.of(2026, 7, 20, 12, 34, 56, 0, ZoneOffset.UTC);
        OffsetDateTime last = SchedulerSupervisor.mostRecentFireTimeBefore("0 * * * * *", now);
        assertThat(last).isEqualTo(OffsetDateTime.of(2026, 7, 20, 12, 34, 0, 0, ZoneOffset.UTC));
    }
}
