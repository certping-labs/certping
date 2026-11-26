// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CaOrderPollingTest {

    private static final Instant PLACED = Instant.parse("2026-10-23T12:00:00Z");
    private final CaOrderPolling polling = new CaOrderPolling(
            List.of(Duration.ofSeconds(15), Duration.ofSeconds(30), Duration.ofSeconds(60)), Duration.ofMinutes(5));

    @Test
    void eachIntervalLastsFourTimesItsLengthAndTheLastOneForever() {
        assertThat(polling.nextDelay(PLACED, PLACED)).isEqualTo(Duration.ofSeconds(15));
        assertThat(polling.nextDelay(PLACED, PLACED.plusSeconds(59))).isEqualTo(Duration.ofSeconds(15));
        assertThat(polling.nextDelay(PLACED, PLACED.plusSeconds(60))).isEqualTo(Duration.ofSeconds(30));
        assertThat(polling.nextDelay(PLACED, PLACED.plusSeconds(179))).isEqualTo(Duration.ofSeconds(30));
        assertThat(polling.nextDelay(PLACED, PLACED.plusSeconds(180))).isEqualTo(Duration.ofSeconds(60));
        assertThat(polling.nextDelay(PLACED, PLACED.plusSeconds(3600))).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void anUnknownPlacementTimeStartsAtTheFirstInterval() {
        assertThat(polling.nextDelay(null, PLACED)).isEqualTo(Duration.ofSeconds(15));
        assertThat(polling.pastDeadline(null, PLACED.plusSeconds(99999))).isFalse();
    }

    @Test
    void theDeadlineCountsFromThePlacement() {
        assertThat(polling.pastDeadline(PLACED, PLACED.plusSeconds(300))).isFalse();
        assertThat(polling.pastDeadline(PLACED, PLACED.plusSeconds(301))).isTrue();
    }

    @Test
    void refusesAnEmptyScheduleOrNoDeadline() {
        assertThatThrownBy(() -> new CaOrderPolling(List.of(), Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CaOrderPolling(List.of(Duration.ZERO), Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CaOrderPolling(List.of(Duration.ofSeconds(15)), Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
