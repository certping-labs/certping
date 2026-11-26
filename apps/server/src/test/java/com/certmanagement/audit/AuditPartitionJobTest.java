// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.service.scheduler.JobPolicy;
import com.certmanagement.service.scheduler.JobTier;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.time.Clock;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuditPartitionJobTest {

    private final SchedulerExecutionPolicy policy = mock(SchedulerExecutionPolicy.class);
    private final AuditEventStore store = mock(AuditEventStore.class);
    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final AuditPartitionJob job = new AuditPartitionJob(policy, store, recorder,
            Clock.fixed(Instant.parse("2026-11-30T23:00:00Z"), ZoneOffset.UTC), metrics);

    @Test
    void isARegisteredPlatformObligationWithoutAKillSwitch() {
        JobPolicy entry = JobPolicy.byName(AuditPartitionJob.JOB).orElseThrow();

        assertThat(entry.tier()).isEqualTo(JobTier.PLATFORM_OBLIGATION);
        assertThat(entry.killSwitchFlag()).isNull();
    }

    @Test
    void doesNothingWhenThePolicySaysNo() {
        when(policy.canRun(AuditPartitionJob.JOB)).thenReturn(false);

        job.runScheduled();

        verifyNoInteractions(store, recorder);
    }

    @Test
    void ensuresTheCurrentMonthAndThreeAheadInUtcAndPublishesTheDefaultPartitionCount() {
        when(policy.canRun(AuditPartitionJob.JOB)).thenReturn(true);
        when(store.createPartition(any())).thenReturn(Optional.empty());
        when(store.defaultPartitionRows(anyInt())).thenReturn(2);

        job.runScheduled();

        for (int ahead = 0; ahead <= 3; ahead++) {
            verify(store).createPartition(YearMonth.of(2026, 11).plusMonths(ahead));
        }
        verify(recorder).recordAsync(any());
        assertThat(metrics.get(AuditPartitionJob.DEFAULT_PARTITION_ROWS_METRIC).gauge().value()).isEqualTo(2);
        assertThat(MDC.get("correlationId")).as("the run's correlation id is removed again").isNull();
    }

    @Test
    void oneFailingMonthDoesNotStopTheOthers() {
        YearMonth broken = YearMonth.of(2026, 12);
        when(store.createPartition(any())).thenAnswer(invocation -> {
            YearMonth month = invocation.getArgument(0);
            if (month.equals(broken)) {
                throw new IllegalStateException("lock timeout");
            }
            return Optional.of("audit_events_" + month.toString().replace('-', '_'));
        });

        AuditPartitionJob.Result result = job.run();

        assertThat(result.failed()).containsExactly("audit_events_2026_12");
        assertThat(result.created()).containsExactly("audit_events_2026_11", "audit_events_2027_01", "audit_events_2027_02");
        assertThat(metrics.get(AuditPartitionJob.FAILURES_METRIC).tag("step", "create").counter().count()).isOne();
    }

    @Test
    void aFailedCountSetsTheGaugeToMinusOneNotTheLastValue() {
        when(store.createPartition(any())).thenReturn(Optional.empty());
        when(store.defaultPartitionRows(anyInt())).thenReturn(3).thenThrow(new IllegalStateException("down"));

        job.run();
        AuditPartitionJob.Result failed = job.run();

        assertThat(failed.defaultPartitionRows()).isEqualTo(-1);
        assertThat(metrics.get(AuditPartitionJob.DEFAULT_PARTITION_ROWS_METRIC).gauge().value()).isEqualTo(-1);
        assertThat(metrics.get(AuditPartitionJob.FAILURES_METRIC).tag("step", "default_count").counter().count())
                .isOne();
    }
}
