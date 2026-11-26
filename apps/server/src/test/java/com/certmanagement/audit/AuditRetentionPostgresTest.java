// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * The retention setting and job on PostgreSQL 15, through the real transaction manager and
 * {@code audit_events_drop_partition}: nothing is dropped before a super admin confirms the period; then only
 * whole expired months are dropped, one per transaction, each on record; the default partition, the current month
 * and the months ahead stay; one replica drops at a time; a busy month is left for the next run; the first
 * confirmation and a shortening wait out their grace; and expired months are not recreated.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms", "certping.jobs.audit-retention.cron=0 30 4 * * *",
        "certping.jobs.audit-retention.grace=24h"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditEventStore.class, AuditRecorder.class, AuditAsyncWriter.class, AuditRetentionService.class,
        AuditRetentionJob.class, AuditRetentionPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditRetentionPostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

    private static final DateTimeFormatter SUFFIX = DateTimeFormatter.ofPattern("yyyy_MM");
    /** The oldest month each test starts with. */
    private static final int MONTHS_BACK = 20;

    @TestConfiguration
    static class Beans {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
    }

    @MockitoBean private SchedulerExecutionPolicy executionPolicy;
    @Autowired private AuditEventStore store;
    @Autowired private AuditRetentionService retention;
    @Autowired private AuditRetentionJob job;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private DataSource dataSource;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private MeterRegistry meterRegistry;

    private YearMonth current;

    @BeforeEach
    void seed() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        jdbc.update("DELETE FROM global_settings WHERE key IN (?, ?)",
                AuditRetentionService.CONFIRMED_AT_KEY, AuditRetentionService.GRACE_UNTIL_KEY);
        setting("12", "now() - interval '2 days'");
        current = YearMonth.now(ZoneOffset.UTC);
        for (int month = -MONTHS_BACK; month <= 3; month++) {
            store.createPartition(current.plusMonths(month));
        }
    }

    @AfterEach
    void clearContext() {
        GatewayRequestContext.clear();
    }

    @Test
    void untilASuperAdminConfirmsNothingIsDropped() {

        AuditRetentionJob.Result result = job.run();

        assertThat(result.outcome()).isEqualTo(AuditRetentionJob.Outcome.UNCONFIRMED);
        assertThat(partitions()).contains(partition(current.minusMonths(MONTHS_BACK)));
        assertThat(meterRegistry.get(AuditRetentionJob.CONFIRMED_METRIC).gauge().value()).isZero();
        assertThat(retention.view().confirmed()).isFalse();
    }

    @Test
    void savingTwelveConfirmsItStartsTheGraceAndAfterTheGraceTheExpiredMonthsGo() {
        int adminId = admin();
        GatewayRequestContext.set(adminId, null, "req-confirm", "ops@certping.test");

        var response = new TransactionTemplate(transactionManager).execute(status ->
                retention.update(12, "Keep a year, per policy"));
        GatewayRequestContext.clear();

        assertThat(response.confirmed()).isTrue();
        assertThat(response.previousMonths()).isNull();
        assertThat(response.effectiveFrom()).isAfter(Instant.now().plus(Duration.ofHours(23)));
        assertThat(jdbc.queryForMap("SELECT visibility, actor_user_id, details->'attributes'->>'reason' AS reason,"
                + " details->'attributes'->>'firstConfirmation' AS first FROM audit_events"
                + " WHERE event = 'audit.retention_confirmed'"))
                .containsEntry("visibility", "INTERNAL").containsEntry("actor_user_id", adminId)
                .containsEntry("reason", "Keep a year, per policy").containsEntry("first", "true");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE event = 'audit.retention_changed'",
                Integer.class)).isZero();

        assertThat(job.run().outcome()).isEqualTo(AuditRetentionJob.Outcome.DEFERRED);
        assertThat(partitions()).contains(partition(current.minusMonths(13)));

        graceOver();
        AuditRetentionJob.Result result = job.run();
        assertThat(result.outcome()).isEqualTo(AuditRetentionJob.Outcome.DROPPED);
        assertThat(result.dropped()).hasSize(MONTHS_BACK - 12).contains(partition(current.minusMonths(13)))
                .doesNotContain(partition(current.minusMonths(12)));
    }

    @Test
    void aRunDropsTheWholeExpiredMonthsOnlyAndRecordsEach() {
        ready("6");
        insertAt(current.minusMonths(MONTHS_BACK).atDay(15).atStartOfDay().toInstant(ZoneOffset.UTC), "ancient");
        insertAt(current.minusMonths(6).atDay(1).atStartOfDay().toInstant(ZoneOffset.UTC).minusMillis(1),
                "last moment of the newest expired month");
        insertAt(current.minusMonths(6).atDay(1).atStartOfDay().toInstant(ZoneOffset.UTC),
                "first moment of the oldest kept month");
        insertAt(Instant.now(), "this month");
        insertAt(current.plusMonths(30).atDay(1).atStartOfDay().toInstant(ZoneOffset.UTC), "in the default partition");
        double droppedBefore = counter(AuditRetentionJob.DROPPED_METRIC);
        double runsBefore = runs("dropped");

        AuditRetentionJob.Result result;
        try (AuditScope scope = AuditScope.system(AuditRetentionJob.JOB, null, "corr-retention")) {
            result = job.run();
        }

        List<String> expired = expired(7);
        assertThat(result.outcome()).isEqualTo(AuditRetentionJob.Outcome.DROPPED);
        assertThat(result.cutoff()).isEqualTo(current.minusMonths(6).atDay(1).atStartOfDay().toInstant(ZoneOffset.UTC));
        assertThat(result.dropped()).containsExactlyElementsOf(expired);
        assertThat(partitions()).doesNotContainAnyElementsOf(expired)
                .contains("audit_events_default", partition(current.minusMonths(6)), partition(current),
                        partition(current.plusMonths(3)));
        assertThat(jdbc.queryForList("SELECT summary FROM audit_events WHERE event IS NULL ORDER BY occurred_at",
                String.class)).containsExactly("first moment of the oldest kept month", "this month",
                "in the default partition");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events_default", Integer.class)).isOne();

        // Queued for the async writer after each commit; a previous test's queued rows may land here too.
        await().atMost(Duration.ofSeconds(10)).until(() -> jdbc.queryForObject("SELECT count(*) FROM audit_events"
                + " WHERE event = 'audit.partition_dropped' AND correlation_id = 'corr-retention'", Integer.class)
                == expired.size());
        assertThat(jdbc.queryForList("SELECT resource_name FROM audit_events WHERE event = 'audit.partition_dropped'"
                + " AND visibility = 'INTERNAL' AND outcome = 'SUCCESS' AND actor_job = 'audit-retention'"
                + " AND correlation_id = 'corr-retention' AND details->'attributes'->>'retentionMonths' = '6'"
                + " AND details->'attributes'->>'cutoff' = ? ORDER BY resource_name", String.class,
                result.cutoff().toString())).containsExactlyElementsOf(expired);

        assertThat(counter(AuditRetentionJob.DROPPED_METRIC) - droppedBefore).isEqualTo(expired.size());
        assertThat(runs("dropped") - runsBefore).isOne();
        assertThat(meterRegistry.get(AuditRetentionJob.OLDEST_MONTH_METRIC).gauge().value())
                .isEqualTo(current.minusMonths(6).atDay(1).atStartOfDay().toEpochSecond(ZoneOffset.UTC));
        assertThat(meterRegistry.get(AuditRetentionJob.MONTHS_METRIC).gauge().value()).isEqualTo(6);
        assertThat(meterRegistry.get(AuditRetentionJob.CONFIRMED_METRIC).gauge().value()).isOne();

        AuditRetentionJob.Result again = job.run();
        assertThat(again.outcome()).isEqualTo(AuditRetentionJob.Outcome.NOTHING_EXPIRED);
        assertThat(again.dropped()).isEmpty();
    }

    @Test
    void aShorterPeriodIsRecordedWithItsReasonAndWaitsOutItsGrace() {
        ready("12");
        int adminId = admin();
        GatewayRequestContext.set(adminId, null, "req-retention", "ops@certping.test");

        var response = new TransactionTemplate(transactionManager).execute(status ->
                retention.update(6, "Contract ends in March"));

        assertThat(response.previousMonths()).isEqualTo(12);
        assertThat(response.effectiveFrom()).isAfter(Instant.now().plus(Duration.ofHours(23)));
        assertThat(jdbc.queryForMap("SELECT value, updated_by FROM global_settings WHERE key = 'audit_retention_months'"))
                .containsEntry("value", "6").containsEntry("updated_by", (long) adminId);
        assertThat(jdbc.queryForMap("SELECT visibility, outcome, actor_user_id, actor_label, summary, request_id,"
                + " details->'changes'->0->>'before' AS before, details->'changes'->0->>'after' AS after,"
                + " details->'attributes'->>'reason' AS reason, details->'attributes'->>'effectiveFrom' AS effective"
                + " FROM audit_events WHERE event = 'audit.retention_changed'"))
                .containsEntry("visibility", "INTERNAL")
                .containsEntry("outcome", "SUCCESS")
                .containsEntry("actor_user_id", adminId)
                .containsEntry("actor_label", "Ops Admin")
                .containsEntry("summary", "Changed how long audit events are kept to 6 months")
                .containsEntry("request_id", "req-retention")
                .containsEntry("before", "12")
                .containsEntry("after", "6")
                .containsEntry("reason", "Contract ends in March")
                .containsEntry("effective", response.effectiveFrom().toString());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE event = 'audit.retention_confirmed'",
                Integer.class)).isOne();

        GatewayRequestContext.clear();
        assertThat(job.run().outcome()).isEqualTo(AuditRetentionJob.Outcome.DEFERRED);
        assertThat(partitions()).contains(partition(current.minusMonths(7)));
    }

    @Test
    void aLongerPeriodDoesNotDeferAnAlreadyDueRun() {
        ready("12");

        new TransactionTemplate(transactionManager).execute(status -> retention.update(18, "longer history"));
        AuditRetentionJob.Result result = job.run();

        assertThat(result.outcome()).isEqualTo(AuditRetentionJob.Outcome.DROPPED);
        assertThat(result.dropped()).containsExactlyElementsOf(expired(19));
    }

    @Test
    void aSaveRolledBackLeavesNeitherTheSettingNorItsRows() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            retention.update(24, "longer history");
            status.setRollbackOnly();
        });

        assertThat(jdbc.queryForObject("SELECT value FROM global_settings WHERE key = 'audit_retention_months'",
                String.class)).isEqualTo("12");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM global_settings WHERE key = ?", Integer.class,
                AuditRetentionService.CONFIRMED_AT_KEY)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE event LIKE 'audit.retention_%'",
                Integer.class)).isZero();
    }

    @Test
    void whileAnotherReplicaHoldsTheLockARunSkipsAndTheNextOneDrops() throws Exception {
        ready("12");
        try (Connection other = dataSource.getConnection(); Statement sql = other.createStatement()) {
            sql.execute("SELECT pg_advisory_lock(hashtextextended('audit_events_retention', 0))");

            AuditRetentionJob.Result locked = job.run();

            assertThat(locked.outcome()).isEqualTo(AuditRetentionJob.Outcome.LOCKED);
            assertThat(partitions()).contains(partition(current.minusMonths(MONTHS_BACK)));
            sql.execute("SELECT pg_advisory_unlock(hashtextextended('audit_events_retention', 0))");
        }

        assertThat(job.run().outcome()).isEqualTo(AuditRetentionJob.Outcome.DROPPED);
        assertThat(partitions()).doesNotContain(partition(current.minusMonths(MONTHS_BACK)));
    }

    @Test
    void aBusyMonthIsLeftForTheNextRunTheOthersAreDroppedAndTheLockIsReleased() throws Exception {
        ready("12");
        String busy = partition(current.minusMonths(15));
        double partialBefore = runs("partial");
        AuditRetentionJob.Result result;
        try (Connection other = dataSource.getConnection(); Statement sql = other.createStatement()) {
            other.setAutoCommit(false);
            sql.execute("LOCK TABLE " + busy + " IN ACCESS SHARE MODE");

            result = job.run();

            other.rollback();
        }

        List<String> others = new ArrayList<>(expired(13));
        others.remove(busy);
        assertThat(result.outcome()).isEqualTo(AuditRetentionJob.Outcome.PARTIAL);
        assertThat(result.failed()).containsExactly(busy);
        assertThat(result.dropped()).containsExactlyElementsOf(others);
        assertThat(partitions()).contains(busy).doesNotContainAnyElementsOf(others);
        assertThat(runs("partial") - partialBefore).isOne();
        await().atMost(Duration.ofSeconds(10)).until(() -> dropRows("FAILURE").contains(busy));
        assertThat(jdbc.queryForMap("SELECT error_code, resource_name, details->'attributes'->>'sqlState' AS sql_state"
                + " FROM audit_events WHERE event = 'audit.partition_dropped' AND outcome = 'FAILURE'"
                + " AND resource_name = ?", busy))
                .containsEntry("error_code", "RETENTION_DROP_FAILED")
                .containsEntry("resource_name", busy)
                .containsEntry("sql_state", "55P03");
        try (Connection other = dataSource.getConnection(); Statement sql = other.createStatement();
             ResultSet free = sql.executeQuery(
                     "SELECT pg_try_advisory_lock(hashtextextended('audit_events_retention', 0))")) {
            assertThat(free.next()).isTrue();
            assertThat(free.getBoolean(1)).as("the run left the retention lock free").isTrue();
            sql.execute("SELECT pg_advisory_unlock(hashtextextended('audit_events_retention', 0))");
        }

        AuditRetentionJob.Result next = job.run();
        assertThat(next.outcome()).isEqualTo(AuditRetentionJob.Outcome.DROPPED);
        assertThat(next.dropped()).containsExactly(busy);
    }

    @Test
    void aValueEditedOutOfRangeByHandDropsNothingAndIsReported() {
        ready("3");

        AuditRetentionJob.Result result = job.run();

        assertThat(result.outcome()).isEqualTo(AuditRetentionJob.Outcome.INVALID_SETTING);
        assertThat(partitions()).contains(partition(current.minusMonths(MONTHS_BACK)));
        await().atMost(Duration.ofSeconds(10)).until(() -> jdbc.queryForObject(
                "SELECT count(*) FROM audit_events WHERE error_code = 'RETENTION_SETTING_INVALID'", Integer.class) == 1);
    }

    @Test
    void theSingleMonthDropRefusesARecentMonthAndNeverTheDefaultPartition() {
        assertThatThrownBy(() -> new TransactionTemplate(transactionManager).execute(status ->
                store.dropPartition(current.minusMonths(5)))).hasStackTraceContaining("later than six months ago");
        Optional<String> notAttached = new TransactionTemplate(transactionManager).execute(status ->
                store.dropPartition(current.minusMonths(MONTHS_BACK + 5)));
        assertThat(notAttached).isEmpty();
        assertThat(partitions()).contains("audit_events_default", partition(current.minusMonths(5)));
    }

    @Test
    void aMonthOlderThanTheConfirmedRetentionIsNeverCreatedAgain() {
        ready("6");
        assertThat(job.run().outcome()).isEqualTo(AuditRetentionJob.Outcome.DROPPED);

        assertThatThrownBy(() -> store.createPartition(current.minusMonths(7)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("retention cutoff");
        assertThat(partitions()).doesNotContain(partition(current.minusMonths(7)));
        assertThat(store.createPartition(current.minusMonths(6))).isEmpty();
        assertThat(store.retentionCutoffInForce())
                .contains(current.minusMonths(6).atDay(1).atStartOfDay().toInstant(ZoneOffset.UTC));
    }

    /** A confirmed period whose grace is over: runs drop. */
    private void ready(String months) {
        setting(months, "now() - interval '2 days'");
        confirmedLongAgo();
    }

    private void confirmedLongAgo() {
        String longAgo = Instant.now().minus(Duration.ofDays(30)).toString();
        upsert(AuditRetentionService.CONFIRMED_AT_KEY, longAgo);
        upsert(AuditRetentionService.GRACE_UNTIL_KEY, longAgo);
    }

    private void graceOver() {
        upsert(AuditRetentionService.GRACE_UNTIL_KEY, Instant.now().minusSeconds(1).toString());
    }

    private int admin() {
        return jdbc.queryForObject("INSERT INTO users (email, display_name) VALUES "
                + "(md5(random()::text) || '@certping.test', 'Ops Admin') RETURNING id", Integer.class);
    }

    private void upsert(String key, String value) {
        jdbc.update("INSERT INTO global_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET"
                + " value = EXCLUDED.value", key, value);
    }

    private void setting(String value, String updatedAt) {
        jdbc.update("INSERT INTO global_settings (key, value, updated_at) VALUES ('audit_retention_months', ?, "
                + updatedAt + ") ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at,"
                + " updated_by = NULL", value);
    }

    private void insertAt(Instant occurredAt, String summary) {
        store.insert(AuditSanitizerTest.row().occurredAt(occurredAt).summary(summary).build());
    }

    /** The seeded months that ended {@code newest} months ago or earlier, oldest first. */
    private List<String> expired(int newest) {
        List<String> expired = new ArrayList<>();
        for (int month = MONTHS_BACK; month >= newest; month--) {
            expired.add(partition(current.minusMonths(month)));
        }
        return expired;
    }

    private List<String> dropRows(String outcome) {
        return jdbc.queryForList("SELECT resource_name FROM audit_events WHERE event = 'audit.partition_dropped'"
                + " AND outcome = ?", String.class, outcome);
    }

    private List<String> partitions() {
        return jdbc.queryForList("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
                + "WHERE i.inhparent = 'audit_events'::regclass ORDER BY c.relname", String.class);
    }

    private static String partition(YearMonth month) {
        return "audit_events_" + month.format(SUFFIX);
    }

    private double counter(String name) {
        return meterRegistry.get(name).counter().count();
    }

    private double runs(String outcome) {
        return meterRegistry.get(AuditRetentionJob.RUNS_METRIC).tag("outcome", outcome).counter().count();
    }
}
