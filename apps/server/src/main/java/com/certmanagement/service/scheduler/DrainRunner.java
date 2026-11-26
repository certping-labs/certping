// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.repository.CronRunRepository;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Resolves and invokes the {@link DrainableCron} for a given job name.
 * Beans self-register via {@link CronJobFor}; the map is built once at startup.
 *
 * <p>Owns three cross-cutting concerns so every entry point (scheduled fire,
 * startup joiner, supervisor catchup) behaves identically:
 * <ul>
 *   <li>Per-drain correlation id in MDC.</li>
 *   <li>cron_runs counter increment/decrement around the drain.</li>
 *   <li>Per-JVM reentrancy guard — the same cron can't run twice concurrently on this pod.</li>
 *   <li>Stopping mid-run: {@link SchedulerExecutionPolicy#canRun} is re-checked before every
 *       iteration after the first (callers check before the first; flag lookups are cached), so a
 *       kill switch or feature flag turned off stops a running drain within one row.</li>
 *   <li>A per-run budget ({@link SchedulerExecutionPolicy#budgetFor}): at most {@code maxRows}
 *       iterations and {@code maxDuration} of wall-clock time, so re-enabling a feature never drains
 *       an unbounded backlog in one go.</li>
 *   <li>Continuation: a run stopped by its budget marks {@code cron_runs.continuation_due_at}, and
 *       {@link SchedulerSupervisor} runs it again on its next tick (any pod, after a restart too)
 *       until a run drains the backlog and clears the marker. The supervisor finds them through
 *       {@link #isRegistered}, which covers every {@link DrainableCron}, not only the crons it
 *       watches for missed fires.</li>
 * </ul>
 */
@Slf4j
@Component
public class DrainRunner {

    static final int HEARTBEAT_EVERY_N_ROWS = 10;

    /** Why a drain run ended; logged so an operator can tell a finished backlog from a capped one. */
    enum StopReason { DRAINED, PAUSED_BY_POLICY, ROW_BUDGET, TIME_BUDGET }

    private final Map<String, DrainableCron> jobs;
    private final CronRunRepository cronRunRepository;
    private final SchedulerExecutionPolicy executionPolicy;
    private final LongSupplier nanoClock;
    private final Set<String> currentlyRunning = ConcurrentHashMap.newKeySet();

    @Autowired
    public DrainRunner(List<DrainableCron> jobList, CronRunRepository cronRunRepository,
                       SchedulerExecutionPolicy executionPolicy) {
        this(jobList, cronRunRepository, executionPolicy, System::nanoTime);
    }

    /** For tests — inject a controllable monotonic clock. */
    DrainRunner(List<DrainableCron> jobList, CronRunRepository cronRunRepository,
                SchedulerExecutionPolicy executionPolicy, LongSupplier nanoClock) {
        this.cronRunRepository = cronRunRepository;
        this.executionPolicy = executionPolicy;
        this.nanoClock = nanoClock;
        this.jobs = new HashMap<>();
        for (DrainableCron job : jobList) {
            // Unwrap Spring's CGLIB proxy — services with @Transactional are wrapped in a
            // subclass proxy whose .getClass() doesn't carry the target class's annotations.
            Class<?> targetClass = AopUtils.getTargetClass(job);
            CronJobFor annotation = targetClass.getAnnotation(CronJobFor.class);
            if (annotation == null) {
                log.warn("[DrainRunner] {} implements DrainableCron but is missing @CronJobFor — skipping",
                        targetClass.getSimpleName());
                continue;
            }
            DrainableCron prev = jobs.put(annotation.value(), job);
            if (prev != null) {
                throw new IllegalStateException(
                        "Duplicate @CronJobFor name '" + annotation.value()
                        + "' declared by " + AopUtils.getTargetClass(prev).getSimpleName()
                        + " and " + targetClass.getSimpleName());
            }
        }
        log.info("[DrainRunner] Registered {} cron job(s): {}", jobs.size(), jobs.keySet());
    }

    public int runDrain(String jobName) {
        DrainableCron job = jobs.get(jobName);
        if (job == null) {
            throw new IllegalArgumentException("Unknown jobName '" + jobName
                    + "' (registered: " + jobs.keySet() + ")");
        }
        if (!currentlyRunning.add(jobName)) {
            log.info("[DrainRunner] {} already running on this pod — skipping duplicate invocation", jobName);
            return 0;
        }
        String correlationId = "corr-cron-" + jobName + "-" + UUID.randomUUID();
        String parentMdcCorrelationId = MDC.get("correlationId");
        MDC.put("correlationId", correlationId);
        log.info("[DrainRunner] Running {}", jobName);
        try {
            cronRunRepository.increment(jobName);
        } catch (Exception e) {
            log.error("[DrainRunner] cron_runs increment failed for {}: {}", jobName, e.getMessage(), e);
        }
        try {
            SchedulerExecutionPolicy.DrainBudget budget = executionPolicy.budgetFor(jobName);
            long startedNanos = nanoClock.getAsLong();
            long deadline = startedNanos + budget.maxDuration().toNanos();
            int processed = 0;
            StopReason stopReason;
            while (true) {
                stopReason = stopReasonBeforeIteration(jobName, processed, budget, deadline);
                if (stopReason != null) {
                    break;
                }
                if (!drainOneIteration(job, jobName)) {
                    stopReason = StopReason.DRAINED;
                    break;
                }
                processed++;
                if (processed % HEARTBEAT_EVERY_N_ROWS == 0) {
                    heartbeat(jobName);
                }
            }
            logOutcome(jobName, processed, stopReason, budget, Duration.ofNanos(nanoClock.getAsLong() - startedNanos));
            recordContinuation(jobName, stopReason);
            return processed;
        } finally {
            try {
                cronRunRepository.decrement(jobName);
            } catch (Exception e) {
                log.error("[DrainRunner] cron_runs decrement failed for {}: {}", jobName, e.getMessage(), e);
            }
            currentlyRunning.remove(jobName);
            if (parentMdcCorrelationId != null) {
                MDC.put("correlationId", parentMdcCorrelationId);
            } else {
                MDC.remove("correlationId");
            }
        }
    }

    /** Whether {@code jobName} names a registered {@link DrainableCron}. */
    public boolean isRegistered(String jobName) {
        return jobs.containsKey(jobName);
    }

    /** Every registered job name, for the supervisor's continuation pass and the registry test. */
    public Set<String> registeredJobNames() {
        return Set.copyOf(jobs.keySet());
    }

    /**
     * Persists whether the backlog needs another run: marked when a budget stopped the run, cleared
     * when the run drained it. A policy stop leaves the marker as it was: the backlog is unchanged and
     * the continuation, which re-checks the policy, resumes it once the job may run again.
     */
    private void recordContinuation(String jobName, StopReason stopReason) {
        try {
            switch (stopReason) {
                case ROW_BUDGET, TIME_BUDGET -> cronRunRepository.markContinuationDue(jobName);
                case DRAINED -> cronRunRepository.clearContinuation(jobName);
                case PAUSED_BY_POLICY -> { }
            }
        } catch (Exception e) {
            log.error("[DrainRunner] continuation marker not updated for {} ({}): {}", jobName, stopReason,
                    e.getMessage(), e);
        }
    }

    /** {@code null} while the drain may continue, otherwise why it must stop before the next row. */
    private StopReason stopReasonBeforeIteration(String jobName, int processed,
                                                 SchedulerExecutionPolicy.DrainBudget budget, long deadline) {
        if (processed >= budget.maxRows()) {
            return StopReason.ROW_BUDGET;
        }
        if (nanoClock.getAsLong() - deadline >= 0) {
            return StopReason.TIME_BUDGET;
        }
        if (processed > 0 && !executionPolicy.canRun(jobName)) {
            return StopReason.PAUSED_BY_POLICY;
        }
        return null;
    }

    private void heartbeat(String jobName) {
        try {
            cronRunRepository.heartbeat(jobName);
        } catch (Exception e) {
            log.warn("[DrainRunner] heartbeat failed for {}: {}", jobName, e.getMessage());
        }
    }

    private static void logOutcome(String jobName, int processed, StopReason stopReason,
                                   SchedulerExecutionPolicy.DrainBudget budget, Duration took) {
        switch (stopReason) {
            case DRAINED -> log.info("[DrainRunner] {} drained {} row(s) in {}ms", jobName, processed, took.toMillis());
            case PAUSED_BY_POLICY -> log.info("[DrainRunner] {} stopped after {} row(s) in {}ms: paused by policy",
                    jobName, processed, took.toMillis());
            default -> log.warn("[DrainRunner] {} stopped after {} row(s) in {}ms: {} reached (maxRows={}, "
                    + "maxDuration={}); the supervisor continues it on its next tick", jobName, processed,
                    took.toMillis(), stopReason, budget.maxRows(), budget.maxDuration());
        }
    }

    /**
     * Runs one iteration under a per-row requestId scope so each row's log lines and any
     * outbound message keyed on requestId are individually traceable and de-duplicable.
     * Services that need a specific requestId format for downstream contracts (e.g.
     * RenewalTriggerService's per-cert id read by CertResponseProcessor) still override
     * inside their tryProcessOneEligible — that inner scope wins for the duration of
     * their work.
     */
    private boolean drainOneIteration(DrainableCron job, String jobName) {
        String parentRowReq = MDC.get("requestId");
        MDC.put("requestId", "req-" + jobName + "-" + UUID.randomUUID());
        try {
            return job.tryProcessOneEligible();
        } finally {
            if (parentRowReq != null) MDC.put("requestId", parentRowReq);
            else MDC.remove("requestId");
        }
    }
}
