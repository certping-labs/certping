// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CronRun;
import com.certmanagement.repository.CronRunRepository;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Every 5 minutes: detects supervised crons whose last_activity_at is older than the
 * most-recent expected fire time (so nobody caught the fire — deploy at cron minute,
 * cluster restart, etc.) and re-runs them.
 *
 * <p>No leader / no claim gate — every pod whose supervisor tick sees "missed" invokes
 * the drain. Same principle as the on-time @Scheduled path: multiple pods → SKIP LOCKED
 * partitions rows at the row level. If two supervisors fire simultaneously, both increment
 * the counter and cooperate on the drain; if one fires seconds after the other, the
 * second sees last_activity_at bumped past expectedByNow and skips.
 *
 * <p>The same tick continues drains that stopped on their per-run budget with work left
 * ({@code cron_runs.continuation_due_at}, written by {@link DrainRunner}). Continuations cover every
 * {@link DrainableCron} DrainRunner registered, not only the {@link CronDefinition} crons; they ignore
 * {@code maxDelay} (the backlog is still owed) but always respect {@link SchedulerExecutionPolicy#canRun}.
 */
@Slf4j
@Component
public class SchedulerSupervisor {

    private static final Duration MISSED_SLOP = Duration.ofMinutes(2);

    private final CronRunRepository repo;
    private final DrainRunner drainRunner;
    private final SchedulerExecutionPolicy executionPolicy;
    private final Clock clock;
    private final Map<CronDefinition, String> resolvedExpressions;

    @Autowired
    public SchedulerSupervisor(CronRunRepository repo,
                               DrainRunner drainRunner,
                               SchedulerExecutionPolicy executionPolicy,
                               Environment env) {
        this(repo, drainRunner, executionPolicy, Clock.systemUTC(), resolve(env));
    }

    /** For tests — inject a fixed Clock and pre-resolved expressions. */
    SchedulerSupervisor(CronRunRepository repo,
                        DrainRunner drainRunner,
                        SchedulerExecutionPolicy executionPolicy,
                        Clock clock,
                        Map<CronDefinition, String> resolvedExpressions) {
        this.repo = repo;
        this.drainRunner = drainRunner;
        this.executionPolicy = executionPolicy;
        this.clock = clock;
        this.resolvedExpressions = resolvedExpressions;
    }

    /** Convenience test constructor — uses each enum's defaultCronExpression. */
    SchedulerSupervisor(CronRunRepository repo,
                        DrainRunner drainRunner,
                        SchedulerExecutionPolicy executionPolicy,
                        Clock clock) {
        this(repo, drainRunner, executionPolicy, clock, defaultExpressions());
    }

    private static Map<CronDefinition, String> resolve(Environment env) {
        Map<CronDefinition, String> map = new EnumMap<>(CronDefinition.class);
        for (CronDefinition c : CronDefinition.values()) {
            map.put(c, env.getProperty(c.cronPropertyKey(), c.defaultCronExpression));
        }
        return map;
    }

    private static Map<CronDefinition, String> defaultExpressions() {
        Map<CronDefinition, String> map = new EnumMap<>(CronDefinition.class);
        for (CronDefinition c : CronDefinition.values()) {
            map.put(c, c.defaultCronExpression);
        }
        return map;
    }

    @RegisteredJob("scheduler-supervisor")
    @Scheduled(cron = "0 */5 * * * *", zone = "UTC")
    public void supervise() {
        String parentCorr = MDC.get("correlationId");
        MDC.put("correlationId", "corr-supervise-" + UUID.randomUUID());
        try {
            superviseInner();
        } finally {
            if (parentCorr != null) MDC.put("correlationId", parentCorr);
            else MDC.remove("correlationId");
        }
    }

    private void superviseInner() {
        Set<String> caughtUp = catchUpMissedFires();
        continueCappedDrains(caughtUp);
    }

    /**
     * Re-runs every drain whose budget stopped it with work left, unless this tick already ran it.
     * A marker naming a job no longer registered (renamed or removed) is skipped with a warning.
     */
    private void continueCappedDrains(Set<String> alreadyRan) {
        List<String> due;
        try {
            due = repo.findIdleWithContinuationDue(OffsetDateTime.now(clock).minus(SchedulerStartupJoiner.STALE_AFTER));
        } catch (Exception e) {
            log.error("[Supervisor] Could not read drain continuations: {}", e.getMessage(), e);
            return;
        }
        for (String jobName : due) {
            if (alreadyRan.contains(jobName)) {
                continue;
            }
            if (!drainRunner.isRegistered(jobName)) {
                log.warn("[Supervisor] Continuation marked for unknown drain {}; ignoring", jobName);
                continue;
            }
            if (!executionPolicy.canRun(jobName)) {
                log.info("[Supervisor] Continuation of {} held: the job may not run now", jobName);
                continue;
            }
            log.info("[Supervisor] Continuing {}: its last run stopped on the drain budget", jobName);
            try {
                drainRunner.runDrain(jobName);
            } catch (Exception e) {
                log.error("[Supervisor] Continuation drain failed for {}: {}", jobName, e.getMessage(), e);
            }
        }
    }

    /** Re-runs supervised crons whose last fire nobody caught; returns the ones it ran. */
    private Set<String> catchUpMissedFires() {
        Set<String> ran = new HashSet<>();
        OffsetDateTime now = OffsetDateTime.now(clock);
        for (CronDefinition cron : CronDefinition.values()) {
            if (!executionPolicy.canRun(cron.name)) {
                continue;
            }
            OffsetDateTime expectedByNow = mostRecentFireTimeBefore(resolvedExpressions.get(cron), now);
            if (expectedByNow == null) {
                continue;
            }

            Optional<CronRun> lastRun = repo.findById(cron.name);
            boolean missed = lastRun.isEmpty()
                          || lastRun.get().getLastActivityAt()
                                          .isBefore(expectedByNow.minus(MISSED_SLOP));
            if (!missed) {
                continue;
            }

            Duration delay = Duration.between(expectedByNow, now);
            if (delay.compareTo(cron.maxDelay) > 0) {
                log.warn("[Supervisor] Missed {} is {} old, exceeds maxDelay {}; skipping",
                        cron.name, delay, cron.maxDelay);
                continue;
            }

            log.warn("[Supervisor] Missed fire for {} (expected {}, now {}); catching up",
                    cron.name, expectedByNow, now);
            ran.add(cron.name);
            try {
                drainRunner.runDrain(cron.name);
            } catch (Exception e) {
                log.error("[Supervisor] Catchup drain failed for {}: {}", cron.name, e.getMessage(), e);
            }
        }
        return ran;
    }

    /**
     * Most recent time strictly before {@code now} at which {@code expression} would have
     * fired. Spring's CronExpression only exposes {@code next()}, so we walk forward from
     * 35 days ago (covers monthly crons) tracking the last hit before {@code now}.
     */
    static OffsetDateTime mostRecentFireTimeBefore(String expression, OffsetDateTime now) {
        CronExpression expr = CronExpression.parse(expression);
        LocalDateTime candidate = now.minusDays(35).toLocalDateTime();
        LocalDateTime last = null;
        while (true) {
            LocalDateTime nextFire = expr.next(candidate);
            if (nextFire == null || !nextFire.isBefore(now.toLocalDateTime())) {
                break;
            }
            last = nextFire;
            candidate = nextFire.plusSeconds(1);
        }
        return last == null ? null : last.atOffset(ZoneOffset.UTC);
    }
}
