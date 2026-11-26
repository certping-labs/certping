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

import java.sql.SQLException;
import java.time.Clock;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Keeps {@code audit_events} partitioned ahead of time: every six hours it makes sure the current month
 * and the next {@value #MONTHS_AHEAD} exist, so a job that stops running for weeks still leaves every
 * row a month to land in. Each month it creates, or fails to create, is an internal audit row.
 *
 * <p>It then checks the default partition. Rows land there only when their month has no partition, and
 * while they sit there that month cannot be attached; so a non-empty default partition is logged at
 * ERROR, recorded, and exposed as {@code certping_audit_default_partition_rows} for alerting ({@code -1}
 * when the count itself failed). Failures of either step are counted in
 * {@code certping_audit_partition_failures_total{step}}. Every replica runs the check, so each records its own
 * {@code audit.default_partition_not_empty} row per run while the condition lasts.
 *
 * <p>A {@link com.certmanagement.service.scheduler.JobTier#PLATFORM_OBLIGATION} job without a kill
 * switch ({@link JobPolicy#AUDIT_PARTITIONS}): pausing it would eventually send rows to the default
 * partition. Safe on every replica at once: creation is idempotent and serialised by an advisory lock.
 */
@Slf4j
@Component
public class AuditPartitionJob {

    static final String JOB = "audit-partitions";
    static final int MONTHS_AHEAD = 3;
    static final String DEFAULT_PARTITION_ROWS_METRIC = "certping.audit.default.partition.rows";
    /** Months this replica could not create, and default-partition counts that failed: for alerting. */
    static final String FAILURES_METRIC = "certping.audit.partition.failures";
    /** Counting stops here: the alert needs "not empty", not an exact count of a large mistake. */
    static final int DEFAULT_PARTITION_SAMPLE = 10_000;

    private static final DateTimeFormatter PARTITION_SUFFIX = DateTimeFormatter.ofPattern("yyyy_MM");

    private final SchedulerExecutionPolicy executionPolicy;
    private final AuditEventStore store;
    private final AuditRecorder recorder;
    private final Clock clock;
    private final AtomicInteger defaultPartitionRows = new AtomicInteger();
    private final Counter createFailures;
    private final Counter countFailures;

    public AuditPartitionJob(SchedulerExecutionPolicy executionPolicy, AuditEventStore store, AuditRecorder recorder,
                             Clock clock, MeterRegistry meterRegistry) {
        this.executionPolicy = executionPolicy;
        this.store = store;
        this.recorder = recorder;
        this.clock = clock;
        Gauge.builder(DEFAULT_PARTITION_ROWS_METRIC, defaultPartitionRows, AtomicInteger::get)
                .description("Rows in audit_events_default (sampled up to 10000; -1 when the count failed); should be 0")
                .register(meterRegistry);
        this.createFailures = Counter.builder(FAILURES_METRIC)
                .description("Audit partition job failures: a month not created, or the default partition not counted")
                .tag("step", "create").register(meterRegistry);
        this.countFailures = Counter.builder(FAILURES_METRIC)
                .description("Audit partition job failures: a month not created, or the default partition not counted")
                .tag("step", "default_count").register(meterRegistry);
    }

    /** What one run did. */
    record Result(List<String> created, List<String> failed, int defaultPartitionRows) {
    }

    @RegisteredJob(JOB)
    @Scheduled(cron = "${certping.jobs.audit-partitions.cron}", zone = "UTC")
    public void runScheduled() {
        if (!executionPolicy.canRun(JOB)) {
            return;
        }
        String parentCorrelationId = MDC.get("correlationId");
        String correlationId = "corr-cron-" + JOB + "-" + UUID.randomUUID();
        MDC.put("correlationId", correlationId);
        try (AuditScope scope = AuditScope.system(JOB, null, correlationId)) {
            Result result = run();
            log.info("[AuditPartitionJob] created={} failed={} defaultPartitionRows={}",
                    result.created(), result.failed(), result.defaultPartitionRows());
        } finally {
            if (parentCorrelationId != null) {
                MDC.put("correlationId", parentCorrelationId);
            } else {
                MDC.remove("correlationId");
            }
        }
    }

    /** One pass: creates the missing months, then checks the default partition. Never throws. */
    Result run() {
        List<String> created = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        YearMonth current = YearMonth.now(clock);
        for (int ahead = 0; ahead <= MONTHS_AHEAD; ahead++) {
            YearMonth month = current.plusMonths(ahead);
            String name = "audit_events_" + month.format(PARTITION_SUFFIX);
            try {
                store.createPartition(month).ifPresent(partition -> {
                    created.add(partition);
                    recorder.recordAsync(AuditEvents.internal(AuditEventType.AUDIT_PARTITION_CREATED,
                            AuditSubject.builder().name(partition).build()));
                });
            } catch (RuntimeException e) {
                failed.add(name);
                createFailures.increment();
                String sqlState = sqlState(e);
                log.error("[AuditPartitionJob] could not create {} ({}, sqlState={}); retrying next run",
                        name, e.getClass().getSimpleName(), sqlState);
                recorder.recordAsync(AuditEvents.internalFailure(AuditEventType.AUDIT_PARTITION_CREATED,
                        AuditSubject.builder().name(name)
                                .attributes(sqlState == null ? Map.of() : Map.of("sqlState", sqlState)).build(),
                        AuditReason.of("PARTITION_DDL_FAILED")));
            }
        }
        int rows = checkDefaultPartition();
        return new Result(created, failed, rows);
    }

    private int checkDefaultPartition() {
        int rows;
        try {
            rows = store.defaultPartitionRows(DEFAULT_PARTITION_SAMPLE);
        } catch (RuntimeException e) {
            log.error("[AuditPartitionJob] could not count audit_events_default ({})", e.getClass().getSimpleName());
            countFailures.increment();
            // -1, not the last count: an alert on "> 0" must not keep firing, nor stay quiet, on stale data.
            defaultPartitionRows.set(-1);
            return -1;
        }
        defaultPartitionRows.set(rows);
        if (rows > 0) {
            log.error("[AuditPartitionJob] audit_events_default holds {} row(s): their months have no partition."
                    + " Create the partitions and move the rows, or the months cannot be attached", rows);
            recorder.recordAsync(AuditEvents.internalFailure(AuditEventType.AUDIT_DEFAULT_PARTITION_NOT_EMPTY,
                    AuditSubject.builder().name("audit_events_default").count(rows).build(),
                    AuditReason.of("DEFAULT_PARTITION_NOT_EMPTY")));
        }
        return rows;
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
