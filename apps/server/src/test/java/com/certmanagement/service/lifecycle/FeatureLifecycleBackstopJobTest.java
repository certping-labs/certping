// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.scheduler.JobPolicy;
import com.certmanagement.service.scheduler.JobTier;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureLifecycleBackstopJobTest {

    private static final Instant NOW = Instant.parse("2026-10-06T12:00:00Z");

    @Mock private FeatureLifecycleRegistry registry;
    @Mock private FeatureLifecycleSweeper sweeper;
    @Mock private FeatureLifecycleReconciler reconciler;
    @Mock private ForcedTransitionWalker walker;
    @Mock private ForcedTransitionStore transitions;
    @Mock private SchedulerExecutionPolicy executionPolicy;
    @Mock private PlatformPausableLifecycle renewals;
    @Mock private PlatformPausableLifecycle discovery;

    @Test
    void theBaselineSweepIsHeldByItsOpsSwitchButTheForcedTransitionsJobIsNot() {
        JobPolicy sweep = JobPolicy.byName(FeatureLifecycleBackstopJob.JOB_NAME).orElseThrow();
        JobPolicy forced = JobPolicy.byName(FeatureLifecycleBackstopJob.TRANSITIONS_JOB).orElseThrow();

        assertThat(sweep.tier()).isEqualTo(JobTier.PLATFORM_OBLIGATION);
        assertThat(sweep.killSwitchFlag()).isEqualTo(FeatureFlags.FEATURE_LIFECYCLE_RECONCILE);
        assertThat(forced.tier()).isEqualTo(JobTier.PLATFORM_OBLIGATION);
        assertThat(forced.killSwitchFlag()).isNull();
        assertThat(sweep.featureFlags()).isEmpty();
        assertThat(forced.featureFlags()).isEmpty();
    }

    @Test
    void everyPausableFeatureIsSweptUnderOneSharedBudget() {
        when(executionPolicy.canRun(FeatureLifecycleBackstopJob.JOB_NAME)).thenReturn(true);
        when(executionPolicy.budgetFor(FeatureLifecycleBackstopJob.JOB_NAME))
                .thenReturn(new SchedulerExecutionPolicy.DrainBudget(1000, Duration.ofMinutes(2)));
        when(registry.pausable()).thenReturn(List.of(renewals, discovery));

        job().reconcileAll();

        ArgumentCaptor<SweepBudget> budgets = ArgumentCaptor.forClass(SweepBudget.class);
        verify(sweeper).sweep(eq(renewals), budgets.capture(), any(SweepCursor.class));
        verify(sweeper).sweep(eq(discovery), budgets.capture(), any(SweepCursor.class));
        assertThat(budgets.getAllValues().get(0)).isSameAs(budgets.getAllValues().get(1));
        verifyNoInteractions(walker);
    }

    @Test
    void theOpsSwitchOffStopsTheBaselineSweep() {
        when(executionPolicy.canRun(FeatureLifecycleBackstopJob.JOB_NAME)).thenReturn(false);

        job().reconcileAll();

        verifyNoInteractions(registry, sweeper, reconciler, walker);
        verify(executionPolicy, never()).budgetFor(any());
    }

    @Test
    void stalledForcedTransitionsAreTakenOverAndOwedEmailsSent() {
        ForcedTransition stalled = new ForcedTransition(4, "DISCOVERY", ForcedTransition.Scope.GLOBAL, null,
                null, true, null, 9, SweepCursor.Pass.PAUSE, 120);
        when(executionPolicy.canRun(FeatureLifecycleBackstopJob.TRANSITIONS_JOB)).thenReturn(true);
        when(executionPolicy.budgetFor(FeatureLifecycleBackstopJob.TRANSITIONS_JOB))
                .thenReturn(new SchedulerExecutionPolicy.DrainBudget(1000, Duration.ofMinutes(2)));
        when(transitions.findIdle(NOW.minus(FeatureLifecycleBackstopJob.IDLE_BEFORE_TAKEOVER),
                FeatureLifecycleBackstopJob.TRANSITIONS_PER_RUN)).thenReturn(List.of(stalled));

        job().applyStalledTransitions();

        verify(walker).apply(eq(stalled), any(SweepBudget.class));
        verify(reconciler).sendOwedNotifications(FeatureLifecycleBackstopJob.NOTIFICATIONS_PER_RUN);
        verifyNoInteractions(sweeper);
    }

    private FeatureLifecycleBackstopJob job() {
        return new FeatureLifecycleBackstopJob(registry, sweeper, reconciler, walker, transitions, executionPolicy,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }
}
