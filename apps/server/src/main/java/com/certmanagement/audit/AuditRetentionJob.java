// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.service.scheduler.JobPolicy;
import com.certmanagement.service.scheduler.RegisteredJob;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Applies the audit retention setting ({@link AuditRetentionService}): once a day it drops the monthly
 * {@code audit_events} partitions that ended before the first day of (current UTC month − {@code months}). Whole
 * months only, so a row is kept for the period plus up to one month. The default partition, the current month and
 * the months ahead are never dropped: {@code audit_events_drop_partition} only drops an
 * {@code audit_events_YYYY_MM} partition and refuses a month that ended later than six months ago, and the setting
 * cannot go below six months.
 *
 * <p>A run first decides, in a short transaction holding the retention advisory lock
 * ({@code pg_try_advisory_xact_lock}; another replica's run makes this one {@code locked}), whether it may drop:
 * <ul>
 *   <li>not while the stored period is not a whole number from 6 to 36 ({@code invalid_setting});</li>
 *   <li>not before a super admin has confirmed the period ({@code unconfirmed}, a WARN once a day);</li>
 *   <li>not during the grace period of the first confirmation or of a shortening ({@code deferred}).</li>
 * </ul>
 * Then it drops each expired month, oldest first, in a transaction of its own that takes the advisory lock again
 * (transaction-scoped, so a pod that dies never leaves it held; a run that finds it taken mid-way stops and leaves
 * the rest to the replica holding it) and waits at most two seconds for the table lock. A busy month is recorded as
 * a failure and left for the next run; the other months are still dropped. Each dropped month is an internal
 * {@code audit.partition_dropped} row, queued for the async writer once its transaction has committed.
 *
 * <p>A {@link com.certmanagement.service.scheduler.JobTier#PLATFORM_OBLIGATION} job with the kill switch
 * {@code AUDIT_RETENTION_PURGE} ({@link JobPolicy#AUDIT_RETENTION}). Metrics:
 * {@code certping_audit_retention_dropped_partitions_total}, {@code certping_audit_retention_runs_total{outcome}},
 * and the gauges {@code certping_audit_retention_oldest_retained_month_seconds} (the first day of the oldest month
 * still stored, as epoch seconds; 0 until a run has read it), {@code certping_audit_retention_months} and
 * {@code certping_audit_retention_confirmed} (1 confirmed, 0 not, -1 until a run has read it).
 */
@Slf4j
@Component
public class AuditRetentionJob {

    static final String JOB = "audit-retention";
    static final String DROPPED_METRIC = "certping.audit.retention.dropped.partitions";
    static final String RUNS_METRIC = "certping.audit.retention.runs";
    static final String OLDEST_MONTH_METRIC = "certping.audit.retention.oldest.retained.month.seconds";
    static final String MONTHS_METRIC = "certping.audit.retention.months";
    static final String CONFIRMED_METRIC = "certping.audit.retention.confirmed";

    /** How a run ended. */
    enum Outcome {
        /** Every expired month was dropped. */
        DROPPED,
        /** Nothing had expired. */
        NOTHING_EXPIRED,
        /** Some months were dropped, at least one could not be (busy); it is retried next run. */
        PARTIAL,
        /** No month could be dropped, or the run failed before dropping any. */
        FAILED,
        /** The first confirmation or a shortening is in its grace period. */
        DEFERRED,
        /** Another replica's run held the lock. */
        LOCKED,
        /** No super admin has confirmed the period yet; nothing is dropped. */
        UNCONFIRMED,
        /** The stored setting cannot be applied; nothing is dropped. */
        INVALID_SETTING;

        String tag() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** What one run did. */
    record Result(Outcome outcome, int months, Instant cutoff, List<String> dropped, List<String> failed) {

        static Result of(Outcome outcome, int months) {
            return new Result(outcome, months, null, List.of(), List.of());
        }
    }

    /** The decision taken under the lock: drop these months, or stop with this outcome. */
    private record Plan(Outcome stop, int months, Instant cutoff, Map<YearMonth, Long> expired) {
    }

    /** Another replica took the lock between two of this run's transactions. */
    private static final class LockTaken extends RuntimeException {
        LockTaken() {
            super(null, null, false, false);
        }
    }

    private final SchedulerExecutionPolicy executionPolicy;
    private final AuditRetentionService retention;
    private final AuditEventStore store;
    private final AuditRecorder recorder;
    private final Clock clock;
    private final TransactionTemplate transaction;
    private final Counter droppedPartitions;
    private final Map<Outcome, Counter> runs = new EnumMap<>(Outcome.class);
    private final AtomicLong oldestRetainedMonth = new AtomicLong();
    private final AtomicLong retentionMonths = new AtomicLong();
    private final AtomicLong confirmed = new AtomicLong(-1);
    private volatile LocalDate unconfirmedWarnedOn;

    public AuditRetentionJob(SchedulerExecutionPolicy executionPolicy, AuditRetentionService retention,
                             AuditEventStore store, AuditRecorder recorder, Clock clock,
                             PlatformTransactionManager transactionManager, MeterRegistry meterRegistry) {
        this.executionPolicy = executionPolicy;
        this.retention = retention;
        this.store = store;
        this.recorder = recorder;
        this.clock = clock;
        this.transaction = new TransactionTemplate(transactionManager);
        this.droppedPartitions = Counter.builder(DROPPED_METRIC)
                .description("Monthly audit_events partitions dropped by the retention job")
                .register(meterRegistry);
        for (Outcome outcome : Outcome.values()) {
            runs.put(outcome, Counter.builder(RUNS_METRIC)
                    .description("Audit retention runs, by how they ended")
                    .tag("outcome", outcome.tag())
                    .register(meterRegistry));
        }
        Gauge.builder(OLDEST_MONTH_METRIC, oldestRetainedMonth, AtomicLong::get)
                .description("First day of the oldest audit_events month still stored, as epoch seconds; 0 when unknown")
                .register(meterRegistry);
        Gauge.builder(MONTHS_METRIC, retentionMonths, AtomicLong::get)
                .description("The audit retention period in months the last run read; 0 when unknown")
                .register(meterRegistry);
        Gauge.builder(CONFIRMED_METRIC, confirmed, AtomicLong::get)
                .description("Whether a super admin has confirmed the audit retention period: 1 yes, 0 no, -1 unknown")
                .register(meterRegistry);
    }

    @RegisteredJob(JOB)
    @Scheduled(cron = "${certping.jobs.audit-retention.cron}", zone = "UTC")
    public void runScheduled() {
        if (!executionPolicy.canRun(JOB)) {
            return;
        }
        String parentCorrelationId = MDC.get("correlationId");
        String correlationId = "corr-cron-" + JOB + "-" + UUID.randomUUID();
        MDC.put("correlationId", correlationId);
        try (AuditScope scope = AuditScope.system(JOB, null, correlationId)) {
            Result result = run();
            log.info("[AuditRetentionJob] outcome={} months={} cutoff={} dropped={} failed={}",
                    result.outcome(), result.months(), result.cutoff(), result.dropped(), result.failed());
        } finally {
            if (parentCorrelationId != null) {
                MDC.put("correlationId", parentCorrelationId);
            } else {
                MDC.remove("correlationId");
            }
        }
    }

    /** One run. Never throws: a failure is logged, counted and recorded, and the next run tries again. */
    Result run() {
        Result result;
        try {
            Plan plan = transaction.execute(status -> plan());
            result = plan.stop() != null ? stopped(plan) : drop(plan);
        } catch (RuntimeException e) {
            result = failedRun(e);
        }
        runs.get(result.outcome()).increment();
        droppedPartitions.increment(result.dropped().size());
        refreshOldestRetainedMonth();
        return result;
    }

    /** Under the lock: whether this run may drop, and what. */
    private Plan plan() {
        if (!store.tryRetentionLock()) {
            return new Plan(Outcome.LOCKED, 0, null, Map.of());
        }
        AuditRetentionService.Setting setting = retention.current();
        confirmed.set(setting.confirmed() ? 1 : 0);
        if (!setting.usable()) {
            return new Plan(Outcome.INVALID_SETTING, setting.months(), null, Map.of());
        }
        retentionMonths.set(setting.months());
        if (!setting.confirmed()) {
            return new Plan(Outcome.UNCONFIRMED, setting.months(), null, Map.of());
        }
        Instant now = clock.instant();
        if (retention.inGrace(setting, now)) {
            return new Plan(Outcome.DEFERRED, setting.months(), null, Map.of());
        }
        Instant cutoff = AuditRetentionService.cutoff(YearMonth.from(now.atZone(ZoneOffset.UTC)), setting.months());
        Map<YearMonth, Long> expired = new LinkedHashMap<>();
        store.estimatedRowsOfPartitionsBefore(cutoff).forEach((partition, estimate) ->
                expired.put(YearMonth.parse(partition.substring("audit_events_".length()).replace('_', '-')), estimate));
        return new Plan(null, setting.months(), cutoff, expired);
    }

    private Result stopped(Plan plan) {
        switch (plan.stop()) {
            case INVALID_SETTING -> {
                log.error("[AuditRetentionJob] global_settings.{} cannot be applied; nothing is dropped until a super"
                        + " admin saves a period from {} to {} months", AuditRetentionService.SETTING_KEY,
                        AuditRetentionService.MIN_MONTHS, AuditRetentionService.MAX_MONTHS);
                recorder.recordFailure(AuditEvents.internalFailure(AuditEventType.AUDIT_PARTITION_DROPPED,
                        AuditSubject.NONE, AuditReason.of("RETENTION_SETTING_INVALID")));
            }
            case UNCONFIRMED -> {
                LocalDate today = LocalDate.now(clock.withZone(ZoneOffset.UTC));
                if (!today.equals(unconfirmedWarnedOn)) {
                    unconfirmedWarnedOn = today;
                    log.warn("[AuditRetentionJob] the audit retention period ({} months) has not been confirmed by a"
                            + " super admin; no audit month is dropped until it is (PUT {})", plan.months(),
                            "/api/v1/admin/settings/audit-retention");
                }
            }
            default -> {
                // LOCKED, DEFERRED: nothing to say beyond the run's own log line.
            }
        }
        return Result.of(plan.stop(), plan.months());
    }

    /** Each expired month in a transaction of its own; a busy one is left for the next run. */
    private Result drop(Plan plan) {
        List<String> dropped = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        boolean lockTaken = false;
        for (Map.Entry<YearMonth, Long> month : plan.expired().entrySet()) {
            String name = "audit_events_" + month.getKey().toString().replace('-', '_');
            try {
                Optional<String> gone = transaction.execute(status -> {
                    if (!store.tryRetentionLock()) {
                        throw new LockTaken();
                    }
                    return store.dropPartition(month.getKey());
                });
                if (gone != null && gone.isPresent()) {
                    dropped.add(gone.get());
                    recordDropped(gone.get(), plan, month.getValue());
                }
            } catch (LockTaken e) {
                lockTaken = true;
                break;
            } catch (RuntimeException e) {
                failed.add(name);
                recordFailedMonth(name, plan, e);
            }
        }
        Outcome outcome;
        if (!failed.isEmpty()) {
            outcome = dropped.isEmpty() ? Outcome.FAILED : Outcome.PARTIAL;
        } else if (dropped.isEmpty()) {
            outcome = lockTaken ? Outcome.LOCKED : Outcome.NOTHING_EXPIRED;
        } else {
            outcome = Outcome.DROPPED;
        }
        return new Result(outcome, plan.months(), plan.cutoff(), dropped, failed);
    }

    private void recordDropped(String partition, Plan plan, Long estimate) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("cutoff", plan.cutoff().toString());
        attributes.put("retentionMonths", Integer.toString(plan.months()));
        if (estimate != null && estimate >= 0) {
            attributes.put("estimatedRows", Long.toString(estimate));
        }
        recorder.recordAsync(AuditEvents.internal(AuditEventType.AUDIT_PARTITION_DROPPED,
                AuditSubject.builder().name(partition).attributes(attributes).build()));
    }

    private void recordFailedMonth(String partition, Plan plan, RuntimeException e) {
        String sqlState = sqlState(e);
        log.error("[AuditRetentionJob] could not drop {} ({}, sqlState={}); retrying next run", partition,
                e.getClass().getSimpleName(), sqlState);
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("cutoff", plan.cutoff().toString());
        attributes.put("retentionMonths", Integer.toString(plan.months()));
        if (sqlState != null) {
            attributes.put("sqlState", sqlState);
        }
        recorder.recordFailure(AuditEvents.internalFailure(AuditEventType.AUDIT_PARTITION_DROPPED,
                AuditSubject.builder().name(partition).attributes(attributes).build(),
                AuditReason.of("RETENTION_DROP_FAILED")));
    }

    private Result failedRun(RuntimeException e) {
        String sqlState = sqlState(e);
        log.error("[AuditRetentionJob] the retention run failed before dropping anything ({}, sqlState={});"
                + " retrying next run", e.getClass().getSimpleName(), sqlState);
        Map<String, String> attributes = new LinkedHashMap<>();
        if (sqlState != null) {
            attributes.put("sqlState", sqlState);
        }
        recorder.recordFailure(AuditEvents.internalFailure(AuditEventType.AUDIT_PARTITION_DROPPED,
                AuditSubject.builder().attributes(attributes).build(), AuditReason.of("RETENTION_DROP_FAILED")));
        return new Result(Outcome.FAILED, 0, null, List.of(), List.of());
    }

    private void refreshOldestRetainedMonth() {
        try {
            oldestRetainedMonth.set(store.oldestPartitionMonth()
                    .map(month -> month.atDay(1).atStartOfDay(ZoneOffset.UTC).toEpochSecond())
                    .orElse(0L));
        } catch (RuntimeException e) {
            log.warn("[AuditRetentionJob] could not read the oldest audit partition ({})",
                    e.getClass().getSimpleName());
        }
    }

    private static String sqlState(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql && sql.getSQLState() != null) {
                return sql.getSQLState();
            }
        }
        return null;
    }
}
