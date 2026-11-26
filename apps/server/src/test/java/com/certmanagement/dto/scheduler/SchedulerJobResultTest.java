// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.scheduler;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SchedulerJobResultTest {

    @Test
    void builder_populatesFieldsAndDefaults() {
        SchedulerJobResult r = SchedulerJobResult.builder()
                .job("trigger-renewals")
                .dryRun(true)
                .triggered(3)
                .skipped(1)
                .scanned(10)
                .reported(2)
                .wouldTrigger(4)
                .wouldSkip(0)
                .marked(5)
                .alerted(6)
                .daysBeforeExpiry(30)
                .details(List.of(Map.of("k", "v")))
                .errors(List.of(Map.of("e", "x")))
                .note("n")
                .build();

        assertThat(r.getJob()).isEqualTo("trigger-renewals");
        assertThat(r.getDryRun()).isTrue();
        assertThat(r.getTriggered()).isEqualTo(3);
        assertThat(r.getMarked()).isEqualTo(5);
        assertThat(r.getDetails()).hasSize(1);
        assertThat(r.getErrors()).hasSize(1);
        assertThat(r.getTriggeredAt()).isNotBlank();
    }

    @Test
    void defaults_initializeCollectionsAndTimestamp() {
        SchedulerJobResult r = SchedulerJobResult.builder().job("j").build();
        assertThat(r.getDetails()).isEmpty();
        assertThat(r.getErrors()).isEmpty();
        assertThat(r.getTriggeredAt()).isNotBlank();
    }

    @Test
    void skipped_factory_setsZeroCountersAndNote() {
        SchedulerJobResult r = SchedulerJobResult.skipped("flag off");
        assertThat(r.getTriggered()).isZero();
        assertThat(r.getSkipped()).isZero();
        assertThat(r.getNote()).isEqualTo("flag off");
    }
}
