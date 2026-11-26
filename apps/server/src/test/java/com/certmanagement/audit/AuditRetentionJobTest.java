// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.scheduler.JobPolicy;
import com.certmanagement.service.scheduler.JobTier;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** The retention job's registration and its gate; what a run drops is AuditRetentionPostgresTest's. */
class AuditRetentionJobTest {

    @Test
    void itIsAPlatformObligationPausedByItsKillSwitch() {
        assertThat(JobPolicy.byName(AuditRetentionJob.JOB)).hasValueSatisfying(policy -> {
            assertThat(policy.tier()).isEqualTo(JobTier.PLATFORM_OBLIGATION);
            assertThat(policy.killSwitchFlag()).isEqualTo(FeatureFlags.AUDIT_RETENTION_PURGE);
            assertThat(policy.featureFlags()).isEmpty();
        });
    }

    @Test
    void aPausedJobTouchesNothing() {
        SchedulerExecutionPolicy policy = mock(SchedulerExecutionPolicy.class);
        when(policy.canRun(AuditRetentionJob.JOB)).thenReturn(false);
        AuditRetentionService retention = mock(AuditRetentionService.class);
        AuditEventStore store = mock(AuditEventStore.class);
        AuditRecorder recorder = mock(AuditRecorder.class);
        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        AuditRetentionJob job = new AuditRetentionJob(policy, retention, store, recorder, Clock.systemUTC(),
                transactions, meters);

        job.runScheduled();

        verifyNoInteractions(retention, store, recorder, transactions);
        assertThat(meters.get(AuditRetentionJob.RUNS_METRIC).counters())
                .allSatisfy(counter -> assertThat(counter.count()).isZero());
    }
}
