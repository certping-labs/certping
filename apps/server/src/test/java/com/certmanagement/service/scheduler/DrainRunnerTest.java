// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.repository.CronRunRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.aop.framework.ProxyFactory;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DrainRunnerTest {

    private static DrainRunner newRunner(List<? extends DrainableCron> jobs) {
        return new DrainRunner(List.copyOf(jobs), mock(CronRunRepository.class), permissivePolicy());
    }

    /** A policy that always allows and grants a budget no test reaches. */
    static SchedulerExecutionPolicy permissivePolicy() {
        SchedulerExecutionPolicy policy = mock(SchedulerExecutionPolicy.class);
        when(policy.canRun(anyString())).thenReturn(true);
        when(policy.budgetFor(anyString()))
                .thenReturn(new SchedulerExecutionPolicy.DrainBudget(1_000, Duration.ofHours(1)));
        return policy;
    }

    @CronJobFor("job-a")
    static class JobA implements DrainableCron {
        final AtomicInteger calls = new AtomicInteger();
        final int returnTrueFor;
        JobA()               { this(0); }
        JobA(int returnTrueFor) { this.returnTrueFor = returnTrueFor; }
        @Override public boolean tryProcessOneEligible() {
            return calls.incrementAndGet() <= returnTrueFor;
        }
    }

    @CronJobFor("job-b")
    static class JobB implements DrainableCron {
        final AtomicInteger calls = new AtomicInteger();
        @Override public boolean tryProcessOneEligible() {
            calls.incrementAndGet();
            return false;
        }
    }

    @CronJobFor("job-a")
    static class JobADuplicate implements DrainableCron {
        @Override public boolean tryProcessOneEligible() { return false; }
    }

    static class UnannotatedJob implements DrainableCron {
        @Override public boolean tryProcessOneEligible() { return false; }
    }

    @Test
    void runDrain_delegatesToBeanMatchingName() {
        JobA a = new JobA();
        JobB b = new JobB();
        DrainRunner runner = newRunner(List.of(a, b));

        runner.runDrain("job-a");

        assertThat(a.calls.get()).isEqualTo(1);
        assertThat(b.calls.get()).isZero();
    }

    @Test
    void runDrain_loopsUntilFalse_returnsProcessedCount() {
        JobA a = new JobA(3);   // returns true for calls 1..3, false on 4th
        DrainRunner runner = newRunner(List.of(a));

        int processed = runner.runDrain("job-a");

        assertThat(processed).isEqualTo(3);
        assertThat(a.calls.get()).isEqualTo(4);
    }

    @Test
    void unknownJobName_throws() {
        DrainRunner runner = newRunner(List.of(new JobA()));

        assertThatThrownBy(() -> runner.runDrain("does-not-exist"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does-not-exist");
    }

    @Test
    void duplicateAnnotationName_throwsAtStartup() {
        assertThatThrownBy(() -> newRunner(List.of(new JobA(), new JobADuplicate())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate @CronJobFor name 'job-a'");
    }

    @Test
    void unannotatedBean_isSkippedButOtherRegistrationsWork() {
        JobA a = new JobA();
        DrainRunner runner = newRunner(List.of(new UnannotatedJob(), a));

        runner.runDrain("job-a");

        assertThat(a.calls.get()).isEqualTo(1);
    }

    @Test
    @Timeout(10)
    void sameCronConcurrentOnSamePod_secondInvocationReturnsZeroWithoutRunning() throws Exception {
        // First invocation is mid-drain; second invocation from another thread must skip.
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        AtomicInteger tries = new AtomicInteger();

        @CronJobFor("slow-job")
        class SlowJob implements DrainableCron {
            @Override public boolean tryProcessOneEligible() {
                // Count before signalling: the latch's happens-before only covers writes made
                // before countDown, so the main thread's assertion would otherwise race the increment.
                tries.incrementAndGet();
                firstStarted.countDown();
                // Bounded, and longer than the main thread's wait, so a body entered by mistake
                // ends instead of hanging, and a slow main thread can't free the guard early.
                try { releaseFirst.await(8, TimeUnit.SECONDS); } catch (InterruptedException ignored) { }
                return false;
            }
        }

        DrainRunner runner = newRunner(List.of(new SlowJob()));
        Thread t1 = new Thread(() -> runner.runDrain("slow-job"));
        t1.setDaemon(true);
        t1.start();
        try {
            assertThat(firstStarted.await(5, TimeUnit.SECONDS)).as("first drain started").isTrue();

            int processed = runner.runDrain("slow-job");   // second invocation while first is blocked

            assertThat(processed).isZero();
            assertThat(tries.get()).isEqualTo(1);   // job body only entered by t1
        } finally {
            releaseFirst.countDown();
            t1.join(5_000);
        }
    }

    @Test
    void reentrancyGuard_clearsAfterCompletion() {
        JobA a = new JobA();
        DrainRunner runner = newRunner(List.of(a));

        runner.runDrain("job-a");
        runner.runDrain("job-a");

        assertThat(a.calls.get()).isEqualTo(2);   // both invocations ran (sequentially)
    }

    /**
     * Guards against the CGLIB-proxy regression: services with @Transactional on
     * tryProcessOneEligible get wrapped in a subclass proxy whose .getClass() no
     * longer carries the target's annotations. DrainRunner must unwrap via
     * AopUtils.getTargetClass, or those services silently drop from the registry.
     */
    @Test
    void cglibProxiedBean_isRegisteredViaTargetClass() {
        JobA target = new JobA();
        ProxyFactory pf = new ProxyFactory(target);
        pf.setProxyTargetClass(true);   // force CGLIB (subclass) proxy
        DrainableCron proxy = (DrainableCron) pf.getProxy();

        assertThat(proxy.getClass()).isNotEqualTo(JobA.class);   // sanity: it's a proxy
        assertThat(proxy.getClass().getAnnotation(CronJobFor.class)).isNull();

        DrainRunner runner = newRunner(List.of(proxy));
        runner.runDrain("job-a");

        assertThat(target.calls.get()).isEqualTo(1);
    }

    @Test
    void runDrain_incrementsBeforeDrainAndDecrementsAfter() {
        JobA a = new JobA();
        CronRunRepository repo = mock(CronRunRepository.class);
        DrainRunner runner = new DrainRunner(List.of(a), repo, permissivePolicy());

        runner.runDrain("job-a");

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(repo);
        order.verify(repo).increment("job-a");
        order.verify(repo).decrement("job-a");
    }

    @Test
    void runDrain_decrementFiresEvenWhenJobThrows() {
        @CronJobFor("throw-job")
        class ThrowingJob implements DrainableCron {
            @Override public boolean tryProcessOneEligible() { throw new RuntimeException("boom"); }
        }
        CronRunRepository repo = mock(CronRunRepository.class);
        DrainRunner runner = new DrainRunner(List.of(new ThrowingJob()), repo, permissivePolicy());

        assertThatThrownBy(() -> runner.runDrain("throw-job")).isInstanceOf(RuntimeException.class);

        verify(repo).increment("throw-job");
        verify(repo).decrement("throw-job");
    }

    @Test
    void runDrain_swallowsIncrementFailureAndStillRunsDrain() {
        JobA a = new JobA();
        CronRunRepository repo = mock(CronRunRepository.class);
        org.mockito.Mockito.doThrow(new RuntimeException("db-blip")).when(repo).increment("job-a");
        DrainRunner runner = new DrainRunner(List.of(a), repo, permissivePolicy());

        runner.runDrain("job-a");   // must not throw

        assertThat(a.calls.get()).isEqualTo(1);
        verify(repo).decrement("job-a");
    }

    @Test
    void runDrain_mintsUniqueRequestIdPerRow() {
        // Capture MDC requestId at each iteration into a list.
        java.util.List<String> requestIds = new java.util.ArrayList<>();

        @CronJobFor("multi-row")
        class MultiRowJob implements DrainableCron {
            int calls;
            @Override public boolean tryProcessOneEligible() {
                requestIds.add(org.slf4j.MDC.get("requestId"));
                return ++calls < 3;   // process 3 rows, then stop
            }
        }

        newRunner(List.of(new MultiRowJob())).runDrain("multi-row");

        assertThat(requestIds).hasSize(3);
        // Every row saw a non-null req id, unique to that row, prefixed by the job name.
        requestIds.forEach(id -> assertThat(id).startsWith("req-multi-row-"));
        assertThat(java.util.Set.copyOf(requestIds)).hasSize(3);   // all distinct
    }

    @Test
    void runDrain_heartbeatsEveryNRows() {
        JobA a = new JobA(25);   // returns true 25 times, false on 26th → 25 processed rows
        CronRunRepository repo = mock(CronRunRepository.class);
        new DrainRunner(List.of(a), repo, permissivePolicy()).runDrain("job-a");

        // HEARTBEAT_EVERY_N_ROWS = 10 → heartbeats at rows 10 and 20 (not at 25).
        verify(repo, org.mockito.Mockito.times(2)).heartbeat("job-a");
    }

    @Test
    void runDrain_noHeartbeatWhenBelowThreshold() {
        JobA a = new JobA(3);   // 3 rows processed
        CronRunRepository repo = mock(CronRunRepository.class);
        new DrainRunner(List.of(a), repo, permissivePolicy()).runDrain("job-a");

        verify(repo, org.mockito.Mockito.never()).heartbeat(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void runDrain_swallowsHeartbeatFailureAndKeepsDraining() {
        JobA a = new JobA(15);
        CronRunRepository repo = mock(CronRunRepository.class);
        org.mockito.Mockito.doThrow(new RuntimeException("db-blip")).when(repo).heartbeat("job-a");

        int processed = new DrainRunner(List.of(a), repo, permissivePolicy()).runDrain("job-a");

        assertThat(processed).isEqualTo(15);
        verify(repo).decrement("job-a");
    }

    @Test
    void runDrain_restoresParentRequestIdAfterEachIteration() {
        String parent = "req-parent-fixed";
        org.slf4j.MDC.put("requestId", parent);
        try {
            JobA a = new JobA(2);   // returns true twice, then false
            newRunner(List.of(a)).runDrain("job-a");
            assertThat(org.slf4j.MDC.get("requestId")).isEqualTo(parent);
        } finally {
            org.slf4j.MDC.remove("requestId");
        }
    }

    // ── policy re-check and per-run budget ─────────────────────────────

    @Test
    void runDrain_stopsMidRunWhenThePolicyTurnsOff() {
        JobA a = new JobA(100);
        SchedulerExecutionPolicy policy = permissivePolicy();
        // Allowed for rows 2 and 3, then the feature is switched off.
        when(policy.canRun("job-a")).thenReturn(true, true, false);

        int processed = new DrainRunner(List.of(a), mock(CronRunRepository.class), policy).runDrain("job-a");

        assertThat(processed).isEqualTo(3);
        assertThat(a.calls.get()).isEqualTo(3);
    }

    @Test
    void runDrain_stopsAtTheRowBudget() {
        JobA a = new JobA(100);
        SchedulerExecutionPolicy policy = permissivePolicy();
        when(policy.budgetFor("job-a")).thenReturn(new SchedulerExecutionPolicy.DrainBudget(5, Duration.ofHours(1)));

        int processed = new DrainRunner(List.of(a), mock(CronRunRepository.class), policy).runDrain("job-a");

        assertThat(processed).isEqualTo(5);
        assertThat(a.calls.get()).isEqualTo(5);
    }

    @Test
    void runDrain_stopsAtTheTimeBudget() {
        JobA a = new JobA(100);
        SchedulerExecutionPolicy policy = permissivePolicy();
        when(policy.budgetFor("job-a")).thenReturn(new SchedulerExecutionPolicy.DrainBudget(1_000, Duration.ofSeconds(10)));
        java.util.concurrent.atomic.AtomicLong now = new java.util.concurrent.atomic.AtomicLong();
        // Every clock read advances 3s: the deadline (start + 10s) passes before the 4th row.
        java.util.function.LongSupplier clock = () -> now.getAndAdd(Duration.ofSeconds(3).toNanos());

        int processed = new DrainRunner(List.of(a), mock(CronRunRepository.class), policy, clock).runDrain("job-a");

        assertThat(processed).isEqualTo(3);
    }

    @Test
    void runDrain_doesNotRecheckThePolicyBeforeTheFirstRow() {
        JobA a = new JobA(0);
        SchedulerExecutionPolicy policy = permissivePolicy();

        new DrainRunner(List.of(a), mock(CronRunRepository.class), policy).runDrain("job-a");

        verify(policy, org.mockito.Mockito.never()).canRun("job-a");
        assertThat(a.calls.get()).isEqualTo(1);
    }
}
