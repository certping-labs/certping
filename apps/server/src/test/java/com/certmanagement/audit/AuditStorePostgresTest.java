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
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Clock;
import java.time.Duration;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * The store, the recorder's three write paths and the partition job on PostgreSQL 15, through the
 * Spring proxies and the real transaction manager.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditEventStore.class, AuditRecorder.class, AuditAsyncWriter.class, AuditPartitionJob.class,
        AuditStorePostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditStorePostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

    private static final DateTimeFormatter SUFFIX = DateTimeFormatter.ofPattern("yyyy_MM");

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
    @Autowired private AuditRecorder recorder;
    @Autowired private AuditPartitionJob partitionJob;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private MeterRegistry meterRegistry;

    private long organizationId;
    private int aliceId;
    private int bobId;

    @BeforeEach
    void seed() {
        // The rows are append-only; only a superuser with triggers off can clear them between tests.
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        YearMonth now = YearMonth.now(ZoneOffset.UTC);
        for (int ahead = 0; ahead <= AuditPartitionJob.MONTHS_AHEAD; ahead++) {
            store.createPartition(now.plusMonths(ahead));
        }
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
        organizationId = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id",
                Long.class);
        aliceId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('alice@acme.test', 'Alice Admin', ?) RETURNING id", Integer.class, organizationId);
        bobId = jdbc.queryForObject("INSERT INTO users (email, organization_id) VALUES ('bob@acme.test', ?) RETURNING id",
                Integer.class, organizationId);
    }

    @AfterEach
    void clearContext() {
        GatewayRequestContext.clear();
    }

    @Test
    void aRecordedRowHasEveryColumnWithTheActorAndOrganizationSnapshotted() {
        GatewayRequestContext.set(aliceId, String.valueOf(organizationId), "req-1", "alice@acme.test");
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("credentialType", "DNS");
        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_UPDATED, AuditSubject.builder()
                .resourceRef("cred-1").name("prod-azure").provider("Azure").attributes(attributes)
                .changes(List.of(new AuditChange("clientSecret", null, "s3cr3t"))).build());

        inTransaction(() -> recorder.record(row));

        Map<String, Object> stored = jdbc.queryForMap("SELECT * FROM audit_events");
        assertThat(stored).containsEntry("visibility", "CUSTOMER")
                .containsEntry("event", "credential.updated")
                .containsEntry("category", "CREDENTIALS")
                .containsEntry("feature_key", "CREDENTIALS_MANAGEMENT")
                .containsEntry("organization_id", organizationId)
                .containsEntry("actor_type", "USER")
                .containsEntry("actor_user_id", aliceId)
                .containsEntry("actor_label", "Alice Admin")
                .containsEntry("actor_staff", false)
                .containsEntry("action", "UPDATE")
                .containsEntry("resource_type", "CREDENTIAL")
                .containsEntry("resource_ref", "cred-1")
                .containsEntry("resource_name", "prod-azure")
                .containsEntry("outcome", "SUCCESS")
                .containsEntry("summary", "Changed the Azure DNS credential 'prod-azure'")
                .containsEntry("request_id", "req-1");
        assertThat(jdbc.queryForList("SELECT column_name FROM information_schema.columns "
                + "WHERE table_name = 'audit_events'", String.class)).doesNotContain("organization_name");
        assertThat(jdbc.queryForObject("SELECT details = CAST(? AS jsonb) FROM audit_events", Boolean.class,
                "{\"kind\":\"event\",\"changes\":[{\"field\":\"clientSecret\",\"before\":null,\"after\":null}],"
                        + "\"attributes\":{\"credentialType\":\"DNS\"}}")).isTrue();
    }

    @Test
    void aBatchIsOneCallAndLabelsFallBackToEmailOrNothing() {
        store.insertAll(List.of(
                AuditSanitizerTest.row().summary("one").actorType(AuditActorType.USER).actorUserId(bobId).build(),
                AuditSanitizerTest.row().summary("two").actorType(AuditActorType.USER).actorUserId(999_999).build(),
                AuditSanitizerTest.row().summary("three").organizationId(organizationId).build()));

        assertThat(jdbc.queryForList("SELECT summary || ':' || coalesce(actor_label, '-') || ':' "
                + "|| coalesce(organization_id::text, '-') FROM audit_events ORDER BY id", String.class))
                .containsExactly("one:bob@acme.test:-", "two:-:-", "three:-:" + organizationId);
    }

    @Test
    void recordNeedsTheCallersTransaction() {
        AuditEventRow row = AuditEvents.success(AuditEventType.CREDENTIAL_DELETED, AuditSubject.NONE);

        assertThatThrownBy(() -> recorder.record(row)).isInstanceOf(IllegalTransactionStateException.class);
        assertThat(count()).isZero();
    }

    @Test
    void aRolledBackChangeLosesItsSuccessRowButKeepsTheFailureRow() {
        GatewayRequestContext.set(aliceId, String.valueOf(organizationId), "req-2", "alice@acme.test");

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            recorder.record(AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                    AuditSubject.builder().name("kept?").build()));
            recorder.recordFailure(AuditEvents.failure(AuditEventType.CREDENTIAL_DELETED,
                    AuditSubject.builder().name("prod-azure").build(), AuditReason.of("AZURE_PERMISSION_DENIED")));
            status.setRollbackOnly();
        });

        await().atMost(Duration.ofSeconds(10)).until(() -> count() == 1);
        assertThat(jdbc.queryForMap("SELECT outcome, error_code, summary, request_id FROM audit_events"))
                .containsEntry("outcome", "FAILURE")
                .containsEntry("error_code", "AZURE_PERMISSION_DENIED")
                .containsEntry("summary", "Could not delete the credential 'prod-azure'")
                .containsEntry("request_id", "req-2");
    }

    @Test
    void aDurableFailureIsWrittenBeforeItReturnsWhateverTheCallerDoes() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            assertThat(recorder.recordFailureDurable(AuditEvents.failure(AuditEventType.CREDENTIAL_DELETED,
                    AuditSubject.NONE, AuditReason.of("EXPORT_LIMIT")))).isTrue();
            status.setRollbackOnly();
        });

        assertThat(count()).isOne();
    }

    @Test
    void pseudonymisingAnActorChangesOnlyTheirLabel() {
        store.insertAll(List.of(
                AuditSanitizerTest.row().summary("alice did").actorType(AuditActorType.USER).actorUserId(aliceId)
                        .ipAddress("203.0.113.9").build(),
                AuditSanitizerTest.row().summary("bob did").actorType(AuditActorType.USER).actorUserId(bobId).build()));

        assertThat(store.pseudonymiseActor(aliceId)).isOne();
        assertThat(store.pseudonymiseActor(aliceId)).as("already pseudonymised").isZero();

        assertThat(jdbc.queryForList("SELECT summary || ':' || actor_label || ':' || coalesce(ip_address, '-') "
                + "FROM audit_events ORDER BY id", String.class))
                .containsExactly("alice did:Former member:203.0.113.9", "bob did:bob@acme.test:-");
        // The erasure switch was cleared again inside the transaction.
        assertThatThrownBy(() -> jdbc.update("UPDATE audit_events SET actor_label = 'Former member'"))
                .hasStackTraceContaining("audit_events is append-only");
    }

    @Test
    void thePartitionJobCreatesAMissingMonthOnceAndRecordsIt() {
        YearMonth last = YearMonth.now(ZoneOffset.UTC).plusMonths(AuditPartitionJob.MONTHS_AHEAD);
        String name = "audit_events_" + last.format(SUFFIX);
        jdbc.execute("DROP TABLE " + name);

        AuditPartitionJob.Result first;
        try (AuditScope scope = AuditScope.system(AuditPartitionJob.JOB, null, "corr-test")) {
            first = partitionJob.run();
        }
        AuditPartitionJob.Result second = partitionJob.run();

        assertThat(first.created()).containsExactly(name);
        assertThat(first.failed()).isEmpty();
        assertThat(first.defaultPartitionRows()).isZero();
        assertThat(second.created()).isEmpty();
        await().atMost(Duration.ofSeconds(10)).until(() -> count() == 1);
        assertThat(jdbc.queryForMap("SELECT visibility, event, actor_type, actor_job, actor_label, resource_name, "
                + "correlation_id FROM audit_events"))
                .containsEntry("visibility", "INTERNAL")
                .containsEntry("event", "audit.partition_created")
                .containsEntry("actor_type", "SYSTEM")
                .containsEntry("actor_job", "audit-partitions")
                .containsEntry("actor_label", "CertPing (automatic)")
                .containsEntry("resource_name", name)
                .containsEntry("correlation_id", "corr-test");
    }

    @Test
    void aMonthWhoseRowsSitInTheDefaultPartitionFailsAndIsReported() {
        YearMonth last = YearMonth.now(ZoneOffset.UTC).plusMonths(AuditPartitionJob.MONTHS_AHEAD);
        String name = "audit_events_" + last.format(SUFFIX);
        jdbc.execute("DROP TABLE " + name);
        store.insert(AuditSanitizerTest.row().summary("stranded")
                .occurredAt(last.atDay(10).atStartOfDay().toInstant(ZoneOffset.UTC)).build());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events_default", Integer.class)).isOne();

        AuditPartitionJob.Result result = partitionJob.run();

        assertThat(result.created()).isEmpty();
        assertThat(result.failed()).containsExactly(name);
        assertThat(result.defaultPartitionRows()).isOne();
        await().atMost(Duration.ofSeconds(10)).until(() -> count() == 3);
        assertThat(jdbc.queryForList("SELECT event || ':' || outcome || ':' || error_code || ':' "
                + "|| coalesce(details->'attributes'->>'sqlState', '-') FROM audit_events WHERE event IS NOT NULL "
                + "ORDER BY event", String.class))
                .containsExactly("audit.default_partition_not_empty:FAILURE:DEFAULT_PARTITION_NOT_EMPTY:-",
                        "audit.partition_created:FAILURE:PARTITION_DDL_FAILED:23514");
    }

    /**
     * A batch with one row Postgres refuses (here through a test-only CHECK constraint, SQLState 23514):
     * the other nine are written row by row, the refused one is counted as rejected, and nothing waits
     * out the 30-second retry window.
     */
    @Test
    void aRefusedRowDoesNotTakeItsBatchWithIt() {
        jdbc.execute("ALTER TABLE audit_events ADD CONSTRAINT test_no_poison CHECK (summary <> 'poison')");
        try {
            double rejectedBefore = rejected();
            for (int i = 0; i < 10; i++) {
                recorder.recordAsync(AuditSanitizerTest.row().summary(i == 6 ? "poison" : "row-" + i).build());
            }

            await().atMost(Duration.ofSeconds(10)).until(() -> rejected() - rejectedBefore == 1 && count() == 9);
            assertThat(jdbc.queryForList("SELECT summary FROM audit_events", String.class)).doesNotContain("poison");
        } finally {
            jdbc.execute("ALTER TABLE audit_events DROP CONSTRAINT test_no_poison");
        }
    }

    private double rejected() {
        return meterRegistry.get(AuditAsyncWriter.DROPPED_METRIC).tag("reason", "rejected").counter().count();
    }

    private int count() {
        Integer rows = jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class);
        return rows == null ? 0 : rows;
    }

    private void inTransaction(Runnable work) {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> work.run());
    }
}
