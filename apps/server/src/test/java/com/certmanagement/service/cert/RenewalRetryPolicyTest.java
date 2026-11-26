// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.RenewalScheduleEntity;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class RenewalRetryPolicyTest {

    @ParameterizedTest
    @CsvSource({"1, 15", "2, 60", "3, 240", "4, 720", "5, 1440", "6, 1440", "40, 1440", "0, 15"})
    void theDelayGrowsWithTheFailuresInARowAndSettlesAtADay(int failures, long baseMinutes) {
        Duration base = Duration.ofMinutes(baseMinutes);

        Duration delay = RenewalRetryPolicy.delayAfter(failures);

        assertThat(delay).isBetween(base, base.plus(base.multipliedBy(RenewalRetryPolicy.JITTER_PERCENT).dividedBy(100)));
    }

    @Test
    void aFailureCountsOneMoreAndFailsTheScheduleUntilItsDelay() {
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .enabled(true).lastRenewalStatus("IN_PROGRESS").consecutiveFailures(2).build();
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        RenewalRetryPolicy.recordFailure(schedule);

        assertThat(schedule.getConsecutiveFailures()).isEqualTo(3);
        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(schedule.getNextAttemptAt()).isAfterOrEqualTo(before.plusHours(4))
                .isBeforeOrEqualTo(OffsetDateTime.now(ZoneOffset.UTC).plusHours(4).plusMinutes(24));
    }

    @Test
    void aScheduleHeldByAFeatureSwitchKeepsItsHoldStatus() {
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .enabled(false).lastRenewalStatus("FEATURE_HOLD").build();

        RenewalRetryPolicy.recordFailure(schedule);

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");
        assertThat(schedule.getConsecutiveFailures()).isEqualTo(1);
        assertThat(schedule.getNextAttemptAt()).isNotNull();
    }

    @Test
    void aScheduleWithoutACountStartsAtTheFirstFailure() {
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder().enabled(true).build();
        schedule.setConsecutiveFailures(null);

        RenewalRetryPolicy.recordFailure(schedule);

        assertThat(schedule.getConsecutiveFailures()).isEqualTo(1);
    }

    @RepeatedTest(3)
    void aHoldIsCheckedAgainAfterAFixedQuarterHour() {
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        assertThat(RenewalRetryPolicy.holdRecheckAt())
                .isBetween(before.plusMinutes(15), OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(15));
    }
}
