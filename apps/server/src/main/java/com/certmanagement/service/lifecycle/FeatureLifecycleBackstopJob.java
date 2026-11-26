// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.scheduler.RegisteredJob;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * The periodic backstops of the feature lifecycle, both PLATFORM_OBLIGATION jobs that must keep running
 * precisely while features are off, each bounded by its {@link SchedulerExecutionPolicy#budgetFor budget}:
 *
 * <ul>
 *   <li>{@value #TRANSITIONS_JOB} applies forced transitions (super admin changes) whose after-commit
 *       run was lost or stalled, continuing a walk from its saved cursor, and sends emails still owed.
 *       It has no ops switch: forced transitions always apply.</li>
 *   <li>{@value #JOB_NAME} is the BASELINE and backstop sweep (catches a record created in a race, an
 *       organization whose feature was already off, and resumes the paused ones whose feature is back
 *       on). Held by the {@code FEATURE_LIFECYCLE_RECONCILE} ops switch; continues where the last run
 *       stopped. Its cursor is per pod and in memory: two pods sweeping the same pages is harmless,
 *       every organization is reconciled under its lock.</li>
 * </ul>
 */
@Slf4j
@Component
public class FeatureLifecycleBackstopJob {

    static final String JOB_NAME = "feature-lifecycle-reconcile";
    static final String TRANSITIONS_JOB = "feature-lifecycle-transitions";
    /** Owed emails sent per run; each is one publish, and a backlog only exists after an outage. */
    static final int NOTIFICATIONS_PER_RUN = 200;
    /** Pending transitions taken over per run. */
    static final int TRANSITIONS_PER_RUN = 50;
    /**
     * How long a pending transition must sit unadvanced before the backstop takes it over; the
     * after-commit walk saves its cursor after every page, well within this.
     */
    static final Duration IDLE_BEFORE_TAKEOVER = Duration.ofMinutes(2);

    private final FeatureLifecycleRegistry registry;
    private final FeatureLifecycleSweeper sweeper;
    private final FeatureLifecycleReconciler reconciler;
    private final ForcedTransitionWalker walker;
    private final ForcedTransitionStore transitions;
    private final SchedulerExecutionPolicy executionPolicy;
    private final Clock clock;
    private final SweepCursor cursor = SweepCursor.fromStart();

    public FeatureLifecycleBackstopJob(FeatureLifecycleRegistry registry, FeatureLifecycleSweeper sweeper,
                                       FeatureLifecycleReconciler reconciler, ForcedTransitionWalker walker,
                                       ForcedTransitionStore transitions, SchedulerExecutionPolicy executionPolicy,
                                       Clock clock) {
        this.registry = registry;
        this.sweeper = sweeper;
        this.reconciler = reconciler;
        this.walker = walker;
        this.transitions = transitions;
        this.executionPolicy = executionPolicy;
        this.clock = clock;
    }

    /** Applies stalled forced transitions and sends owed emails. */
    @RegisteredJob(TRANSITIONS_JOB)
    @Scheduled(fixedDelayString = "${certping.jobs.feature-lifecycle-transitions.fixed-delay:PT1M}",
            initialDelayString = "${certping.jobs.feature-lifecycle-transitions.initial-delay:PT1M}")
    public void applyStalledTransitions() {
        if (!executionPolicy.canRun(TRANSITIONS_JOB)) {
            return;
        }
        withCorrelationId(TRANSITIONS_JOB, () -> {
            SweepBudget budget = budget(TRANSITIONS_JOB);
            List<ForcedTransition> idle = transitions.findIdle(clock.instant().minus(IDLE_BEFORE_TAKEOVER),
                    TRANSITIONS_PER_RUN);
            int reconciled = 0;
            for (ForcedTransition transition : idle) {
                if (budget.isExhausted()) {
                    break;
                }
                reconciled += walker.apply(transition, budget);
            }
            int notified = reconciler.sendOwedNotifications(NOTIFICATIONS_PER_RUN);
            log.info("[FeatureLifecycle] backstop took over {} forced change(s) ({} organization(s)), sent {} owed"
                    + " email(s)", idle.size(), reconciled, notified);
        });
    }

    /** The baseline and backstop sweep, while its ops switch is on. */
    @RegisteredJob(JOB_NAME)
    @Scheduled(fixedDelayString = "${certping.jobs.feature-lifecycle-reconcile.fixed-delay:PT5M}",
            initialDelayString = "${certping.jobs.feature-lifecycle-reconcile.initial-delay:PT2M}")
    public void reconcileAll() {
        if (!executionPolicy.canRun(JOB_NAME)) {
            return;
        }
        withCorrelationId(JOB_NAME, () -> {
            SweepBudget budget = budget(JOB_NAME);
            int reconciled = 0;
            for (PlatformPausableLifecycle lifecycle : registry.pausable()) {
                if (budget.isExhausted()) {
                    break;
                }
                reconciled += sweeper.sweep(lifecycle, budget, cursor);
            }
            log.info("[FeatureLifecycle] baseline sweep reconciled {} organization(s){}", reconciled,
                    budget.isExhausted() ? "; budget reached, the rest continues next run" : "");
        });
    }

    private SweepBudget budget(String jobName) {
        SchedulerExecutionPolicy.DrainBudget limits = executionPolicy.budgetFor(jobName);
        return SweepBudget.of(limits.maxRows(), limits.maxDuration());
    }

    private static void withCorrelationId(String jobName, Runnable work) {
        String parentCorrelationId = MDC.get("correlationId");
        MDC.put("correlationId", "corr-cron-" + jobName + "-" + UUID.randomUUID());
        try {
            work.run();
        } finally {
            if (parentCorrelationId != null) {
                MDC.put("correlationId", parentCorrelationId);
            } else {
                MDC.remove("correlationId");
            }
        }
    }
}
