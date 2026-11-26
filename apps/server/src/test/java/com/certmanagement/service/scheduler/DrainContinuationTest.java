// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CronRun;
import com.certmanagement.repository.CronRunRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A drain stopped by its per-run budget is continued by the supervisor's next tick, from the
 * {@code cron_runs.continuation_due_at} marker, for every registered {@link DrainableCron}.
 */
class DrainContinuationTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-20T07:00:00Z"), ZoneOffset.UTC);

    private final CronRunRepository repo = mock(CronRunRepository.class);
    private final SchedulerExecutionPolicy policy = DrainRunnerTest.permissivePolicy();

    @BeforeEach
    void everySupervisedCronIsFresh() {
        OffsetDateTime justNow = OffsetDateTime.now(CLOCK).minusSeconds(1);
        for (CronDefinition cron : CronDefinition.values()) {
            CronRun run = new CronRun();
            run.setCronName(cron.name);
            run.setLastActivityAt(justNow);
            when(repo.findById(cron.name)).thenReturn(Optional.of(run));
        }
    }

    // ── DrainRunner writes the marker ──────────────────────────────────

    @Test
    void aRunStoppedByTheRowBudgetMarksItsContinuation() {
        when(policy.budgetFor("job-a")).thenReturn(new SchedulerExecutionPolicy.DrainBudget(2, Duration.ofHours(1)));

        new DrainRunner(List.of(new DrainRunnerTest.JobA(10)), repo, policy).runDrain("job-a");

        verify(repo).markContinuationDue("job-a");
        verify(repo, never()).clearContinuation(anyString());
    }

    @Test
    void aRunStoppedByTheTimeBudgetMarksItsContinuation() {
        when(policy.budgetFor("job-a")).thenReturn(new SchedulerExecutionPolicy.DrainBudget(1_000, Duration.ofSeconds(5)));
        AtomicLong nanos = new AtomicLong();

        new DrainRunner(List.of(new DrainRunnerTest.JobA(10)), repo, policy,
                () -> nanos.getAndAdd(Duration.ofSeconds(2).toNanos())).runDrain("job-a");

        verify(repo).markContinuationDue("job-a");
    }

    @Test
    void aDrainedRunClearsTheMarker() {
        new DrainRunner(List.of(new DrainRunnerTest.JobA(3)), repo, policy).runDrain("job-a");

        verify(repo).clearContinuation("job-a");
        verify(repo, never()).markContinuationDue(anyString());
    }

    @Test
    void aPolicyStopLeavesTheMarkerAsItWas() {
        when(policy.canRun("job-a")).thenReturn(false);

        new DrainRunner(List.of(new DrainRunnerTest.JobA(10)), repo, policy).runDrain("job-a");

        verify(repo, never()).markContinuationDue(anyString());
        verify(repo, never()).clearContinuation(anyString());
    }

    @Test
    void aMarkerWriteFailureDoesNotFailTheRun() {
        doThrow(new RuntimeException("db-blip")).when(repo).clearContinuation("job-a");

        int processed = new DrainRunner(List.of(new DrainRunnerTest.JobA(3)), repo, policy).runDrain("job-a");

        assertThat(processed).isEqualTo(3);
        verify(repo).decrement("job-a");
    }

    // ── SchedulerSupervisor continues it ───────────────────────────────

    @Test
    void theSupervisorContinuesADueDrainThatIsNotACronDefinition() {
        DrainRunner runner = mock(DrainRunner.class);
        when(runner.isRegistered("expiry-cleanup")).thenReturn(true);
        when(repo.findIdleWithContinuationDue(any())).thenReturn(List.of("expiry-cleanup"));

        new SchedulerSupervisor(repo, runner, policy, CLOCK).supervise();

        verify(runner).runDrain("expiry-cleanup");
        verify(repo).findIdleWithContinuationDue(OffsetDateTime.now(CLOCK).minus(SchedulerStartupJoiner.STALE_AFTER));
    }

    @Test
    void aContinuationIsHeldWhileTheJobMayNotRun() {
        DrainRunner runner = mock(DrainRunner.class);
        when(runner.isRegistered("soft-delete-purge")).thenReturn(true);
        when(repo.findIdleWithContinuationDue(any())).thenReturn(List.of("soft-delete-purge"));
        when(policy.canRun("soft-delete-purge")).thenReturn(false);

        new SchedulerSupervisor(repo, runner, policy, CLOCK).supervise();

        verify(runner, never()).runDrain(anyString());
    }

    @Test
    void aContinuationIgnoresMaxDelay() {
        // Ten days late: a missed fire that old would be past any maxDelay, but the backlog a
        // capped run left is still owed.
        Clock tenDaysLate = Clock.fixed(Instant.parse("2026-07-11T07:00:00Z"), ZoneOffset.UTC);
        DrainRunner runner = mock(DrainRunner.class);
        when(runner.isRegistered("soft-delete-purge")).thenReturn(true);
        when(repo.findById(anyString())).thenReturn(Optional.empty());
        when(repo.findIdleWithContinuationDue(any()))
                .thenReturn(List.of(), List.of("soft-delete-purge"));
        SchedulerSupervisor supervisor = new SchedulerSupervisor(repo, runner, policy, tenDaysLate);

        supervisor.supervise();
        verify(runner, never()).runDrain("soft-delete-purge");

        supervisor.supervise();
        verify(runner).runDrain("soft-delete-purge");
    }

    @Test
    void aDrainCaughtUpThisTickIsNotContinuedTwice() {
        DrainRunner runner = mock(DrainRunner.class);
        when(runner.isRegistered("mark-expired-certs")).thenReturn(true);
        when(repo.findById("mark-expired-certs")).thenReturn(Optional.empty());
        when(repo.findIdleWithContinuationDue(any())).thenReturn(List.of("mark-expired-certs"));

        new SchedulerSupervisor(repo, runner, policy, CLOCK).supervise();

        verify(runner).runDrain("mark-expired-certs");
    }

    @Test
    void aMarkerForAnUnknownDrainIsIgnored() {
        DrainRunner runner = mock(DrainRunner.class);
        when(repo.findIdleWithContinuationDue(any())).thenReturn(List.of("renamed-job"));

        new SchedulerSupervisor(repo, runner, policy, CLOCK).supervise();

        verify(runner, never()).runDrain(anyString());
    }

    // ── registry: every DrainableCron is reachable ─────────────────────

    @Test
    void everyProductionDrainableCronIsRegisteredAndContinuedFromItsMarker() {
        List<Class<?>> types = ProductionJobScan.drainableCrons();
        List<DrainableCron> beans = types.stream().map(type -> (DrainableCron) mock(type)).toList();
        Set<String> names = types.stream().map(type -> type.getAnnotation(CronJobFor.class).value())
                .collect(Collectors.toSet());
        DrainRunner runner = new DrainRunner(beans, repo, policy);
        when(repo.findIdleWithContinuationDue(any())).thenReturn(List.copyOf(names));

        new SchedulerSupervisor(repo, runner, policy, CLOCK).supervise();

        assertThat(runner.registeredJobNames()).containsExactlyInAnyOrderElementsOf(names).contains("expiry-cleanup");
        beans.forEach(bean -> verify(bean).tryProcessOneEligible());
        names.forEach(name -> verify(repo).clearContinuation(name));
    }
}
