// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditAccessEntryDto;
import com.certmanagement.dto.audit.AuditAccessFilterRequest;
import com.certmanagement.dto.audit.AuditEventEntryDto;
import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.dto.audit.AuditPlatformEntryDto;
import com.certmanagement.dto.audit.AuditPlatformFilterRequest;
import com.certmanagement.dto.audit.AuditTrailPage;
import com.certmanagement.exception.AuditExportRefusedException;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterUtils;
import org.springframework.jdbc.core.namedparam.ParsedSql;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The export and platform views on PostgreSQL 15: the exports (recorded first, refused when that fails, the row cap and the shared hourly
 * limit, the sensitive reads left out, rows fetched through a cursor), the Access view, the platform view
 * (internal rows, every organization, unclamped, 90 days a query) with the staff rows it writes into an
 * organization's trail, and the platform query's plans.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.export-lock-timeout-ms=1000"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditEventStore.class, AuditEventQueryStore.class, AuditTrailReader.class, AuditVisibilityPolicy.class,
        AuditExportAndPlatformPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditExportAndPlatformPostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

    /** Each audit list or stream statement run: its fetch size, and whether it ran with auto-commit off. */
    record Execution(String sql, int fetchSize, boolean autoCommit) {
    }

    static final List<Execution> EXECUTIONS = new CopyOnWriteArrayList<>();

    @TestConfiguration
    static class Beans {
        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        static BeanPostProcessor recordingDataSource() {
            return new BeanPostProcessor() {
                @Override
                public Object postProcessAfterInitialization(Object bean, String name) throws BeansException {
                    return bean instanceof DataSource dataSource && !(bean instanceof RecordingDataSource)
                            ? new RecordingDataSource(dataSource) : bean;
                }
            };
        }
    }

    /** Records how the audit row statements are executed: the proof that an export is read through a cursor. */
    static final class RecordingDataSource extends DelegatingDataSource {
        RecordingDataSource(DataSource target) {
            super(target);
        }

        @Override
        public Connection getConnection() throws SQLException {
            return recording(super.getConnection());
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return recording(super.getConnection(username, password));
        }

        private static Connection recording(Connection connection) {
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                    new Class<?>[]{Connection.class}, (proxy, method, args) -> {
                        Object result = invoke(connection, method, args);
                        if (method.getName().equals("prepareStatement") && args != null && args[0] instanceof String sql
                                && sql.startsWith("SELECT id,") && result instanceof PreparedStatement statement) {
                            return statement(statement, sql, connection);
                        }
                        return result;
                    });
        }

        private static PreparedStatement statement(PreparedStatement target, String sql, Connection connection) {
            return (PreparedStatement) Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),
                    new Class<?>[]{PreparedStatement.class}, (proxy, method, args) -> {
                        if (method.getName().equals("executeQuery") && (args == null || args.length == 0)) {
                            EXECUTIONS.add(new Execution(sql, target.getFetchSize(), connection.getAutoCommit()));
                        }
                        return invoke(target, method, args);
                    });
        }

        private static Object invoke(Object target, java.lang.reflect.Method method, Object[] args) throws Throwable {
            try {
                return method.invoke(target, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
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

    @MockitoBean private FeatureFlagService featureFlags;
    @Autowired private AuditEventStore store;
    @Autowired private AuditEventQueryStore queries;
    @Autowired private AuditTrailReader reader;
    @Autowired private AuditVisibilityPolicy policy;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private DataSource dataSource;

    private final Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
    private final AuditAsyncWriter asyncWriter = mock(AuditAsyncWriter.class);
    private long acme;
    private long globex;
    private int alice;
    private int sam;

    @BeforeEach
    void seed() {
        EXECUTIONS.clear();
        when(featureFlags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        YearMonth month = YearMonth.now(ZoneOffset.UTC);
        for (int back = -5; back <= 1; back++) {
            store.createPartition(month.plusMonths(back));
        }
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
        acme = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id", Long.class);
        globex = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Globex', 'globex.test', 'globex') RETURNING id",
                Long.class);
        alice = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('alice@acme.test', 'Alice Admin', ?) RETURNING id", Integer.class, acme);
        sam = jdbc.queryForObject("INSERT INTO users (email, display_name) VALUES ('sam@example.com', 'Sam Support') "
                + "RETURNING id", Integer.class);
        asMember(alice, acme);
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    // ── Exports ──────────────────────────────────────────────────────────

    @Test
    void theExportRowIsCommittedBeforeTheFirstRowIsReadAndTheRowsComeThroughACursor() throws IOException {
        store.insertAll(IntStream.range(0, 1_200).mapToObj(i -> row(acme, now.minusSeconds(i)).build()).toList());
        AuditTrailExporter.AuditExport export = exporter(10_000, 10).exportActivity(new AuditEventFilterRequest(),
                "csv", false, customer());
        List<Long> exportRowsSeenAtFirstWrite = new ArrayList<>();
        OutputStream out = new ByteArrayOutputStream() {
            @Override
            public void write(byte[] b, int off, int len) {
                if (exportRowsSeenAtFirstWrite.isEmpty()) {
                    // Another connection, outside the export's transaction: the row is committed.
                    exportRowsSeenAtFirstWrite.add(jdbc.queryForObject("SELECT count(*) FROM audit_events "
                            + "WHERE event = 'audit_log.exported' AND organization_id = ?", Long.class, acme));
                }
                super.write(b, off, len);
            }
        };

        export.body().writeTo(out);

        assertThat(exportRowsSeenAtFirstWrite).containsExactly(1L);
        assertThat(out.toString().lines()).hasSize(1_201);
        assertThat(EXECUTIONS).filteredOn(e -> e.fetchSize() == AuditEventQueryStore.EXPORT_FETCH_SIZE)
                .as("the export's rows are fetched %d at a time, inside a transaction",
                        AuditEventQueryStore.EXPORT_FETCH_SIZE)
                .singleElement().satisfies(e -> assertThat(e.autoCommit()).isFalse());
        assertThat(jdbc.queryForObject("SELECT summary FROM audit_events WHERE event = 'audit_log.exported'",
                String.class)).isEqualTo("Exported 1200 audit log entries as CSV");
    }

    @Test
    void theStreamHandsOverChunksOfAtMostTheFetchSizeAndOnlyInsideATransaction() {
        store.insertAll(IntStream.range(0, 1_200).mapToObj(i -> row(acme, now.minusSeconds(i)).build()).toList());
        AuditEventQuery query = AuditEventQuery.builder().organizationId(acme).build();
        List<Integer> chunks = new ArrayList<>();

        long streamed = new TransactionTemplate(transactionManager).execute(status ->
                queries.stream(query, 1_100, chunk -> chunks.add(chunk.size())));

        assertThat(streamed).isEqualTo(1_100);
        assertThat(chunks).containsExactly(500, 500, 100);
        assertThatThrownBy(() -> queries.stream(query, 10, chunk -> { }))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void theActivityExportLeavesOutTheSensitiveReadsAndTheAccessExportHoldsOnlyThem() throws IOException {
        store.insertAll(List.of(row(acme, now.minusSeconds(1)).requestId("change").build(),
                read(acme, now.minusSeconds(2)).requestId("read").build(),
                row(globex, now.minusSeconds(3)).requestId("theirs").build()));
        AuditTrailExporter exporter = exporter(10_000, 10);

        String activity = body(exporter.exportActivity(new AuditEventFilterRequest(), "csv", false, customer()));
        AuditEventFilterRequest accessCategory = new AuditEventFilterRequest();
        accessCategory.setCategory("ACCESS");
        String asked = body(exporter.exportActivity(accessCategory, "csv", false, customer()));
        String access = body(exporter.exportAccess(new AuditAccessFilterRequest(), "csv", customer()));

        assertThat(activity).contains("change").doesNotContain(",read,").doesNotContain("theirs");
        assertThat(asked).contains("read").doesNotContain("change");
        assertThat(access.lines().toList()).hasSize(2).last().asString().contains("access.audit_log_viewed");
        assertThat(jdbc.queryForList("SELECT event FROM audit_events WHERE event LIKE '%log.exported' ORDER BY id",
                String.class)).containsExactly("audit_log.exported", "audit_log.exported", "access_log.exported");
    }

    @Test
    void anExportPastTheCapIsRefusedAndRecordedAsAFailedExport() {
        store.insertAll(IntStream.range(0, 6).mapToObj(i -> row(acme, now.minusSeconds(i)).build()).toList());

        assertThatThrownBy(() -> exporter(5, 10).exportActivity(new AuditEventFilterRequest(), "csv", false,
                customer()))
                .isInstanceOfSatisfying(AuditExportRefusedException.class,
                        refused -> assertThat(refused.getCode()).isEqualTo("EXPORT_TOO_LARGE"));

        assertThat(jdbc.queryForMap("SELECT outcome, error_code FROM audit_events WHERE event = 'audit_log.exported'"))
                .containsEntry("outcome", "FAILURE").containsEntry("error_code", "EXPORT_TOO_LARGE");
    }

    @Test
    void theHourlyLimitIsCountedFromTheExportRowsSoEveryPodSharesIt() {
        store.insert(row(acme, now.minusSeconds(1)).build());
        AuditTrailExporter onePod = exporter(10_000, 2);
        AuditTrailExporter anotherPod = exporter(10_000, 2);

        onePod.exportActivity(new AuditEventFilterRequest(), "csv", false, customer());
        anotherPod.exportAccess(new AuditAccessFilterRequest(), "json", customer());

        assertThatThrownBy(() -> onePod.exportActivity(new AuditEventFilterRequest(), "csv", false, customer()))
                .isInstanceOfSatisfying(AuditExportRefusedException.class, refused -> {
                    assertThat(refused.getCode()).isEqualTo("EXPORT_LIMIT");
                    assertThat(refused.getRetryAfterSeconds()).isBetween(3_500L, 3_600L);
                });
        asMember(alice, globex);
        exporter(10_000, 2).exportActivity(new AuditEventFilterRequest(), "csv", false, policy.viewer(false, globex));
    }

    @Test
    void anExportWhoseRowCannotBeWrittenIsRefusedAndReadsNothing() {
        store.insert(row(acme, now.minusSeconds(1)).build());
        AuditEventStore failing = mock(AuditEventStore.class);
        doThrow(new DataAccessResourceFailureException("audit_events unavailable")).when(failing).insert(any());
        AuditTrailExporter exporter = new AuditTrailExporter(reader, queries, failing, staffReads(),
                JsonMapper.builderWithJackson2Defaults()
                        .findAndAddModules()
                        .build(), Clock.systemUTC(), transactionManager, 10_000, 10, 4);
        EXECUTIONS.clear();

        assertThatThrownBy(() -> exporter.exportActivity(new AuditEventFilterRequest(), "csv", false, customer()))
                .isInstanceOfSatisfying(AuditExportRefusedException.class,
                        refused -> assertThat(refused.getCode()).isEqualTo("EXPORT_NOT_RECORDED"));
        assertThat(EXECUTIONS).as("no row was read").isEmpty();
    }

    @Test
    void anExportWaitingPastTheLockTimeoutForAnotherExportOfTheOrganizationIsAskedToRetry() throws Exception {
        java.util.concurrent.CountDownLatch locked = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        Thread other = new Thread(() -> new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.queryForObject("SELECT 1 FROM (SELECT pg_advisory_xact_lock(hashtextextended('audit-export', ?))) "
                    + "AS held", Integer.class, acme);
            locked.countDown();
            try {
                done.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }));
        other.start();
        try {
            assertThat(locked.await(10, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

            assertThatThrownBy(() -> exporter(10_000, 10).exportActivity(new AuditEventFilterRequest(), "csv", false,
                    customer()))
                    .isInstanceOfSatisfying(AuditExportRefusedException.class, refused -> {
                        assertThat(refused.getCode()).isEqualTo("EXPORT_IN_PROGRESS");
                        assertThat(refused.getRetryAfterSeconds()).isEqualTo(5);
                    });
            assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE event = 'audit_log.exported'",
                    Long.class)).isZero();
        } finally {
            done.countDown();
            other.join(10_000);
        }
        exporter(10_000, 10).exportActivity(new AuditEventFilterRequest(), "csv", false, customer());
    }

    // ── Access view ──────────────────────────────────────────────────────

    @Test
    void theAccessViewListsOnlyTheSensitiveReadsInTheWindowAndPagesByCursor() {
        List<AuditEventRow> rows = new ArrayList<>();
        IntStream.range(0, 5).forEach(i -> rows.add(read(acme, now.minusSeconds(i)).build()));
        rows.add(read(acme, now.minus(Duration.ofDays(100))).requestId("old").build());
        rows.add(row(acme, now).requestId("change").build());
        rows.add(read(globex, now).requestId("theirs").build());
        store.insertAll(rows);

        AuditTrailPage<AuditAccessEntryDto> first = reader.readAccess(new AuditAccessFilterRequest(), 3, customer());
        AuditAccessFilterRequest next = new AuditAccessFilterRequest();
        next.setCursor(first.nextCursor());
        AuditTrailPage<AuditAccessEntryDto> second = reader.readAccess(next, 3, customer());

        assertThat(first.totalElements()).isEqualTo(5);
        assertThat(first.visibleFrom()).isNotNull();
        assertThat(first.content()).hasSize(3).allSatisfy(e -> {
            assertThat(e.activity()).isEqualTo("access.audit_log_viewed");
            assertThat(e.actor()).isEqualTo("Alice Admin");
        });
        assertThat(second.content()).hasSize(2);
        assertThat(second.last()).isTrue();
        assertThat(second.content()).extracting(AuditAccessEntryDto::requestId).doesNotContain("old", "theirs");
    }

    // ── Platform view and staff rows ─────────────────────────────────────

    @Test
    void thePlatformViewReadsInternalRowsAndEveryOrganizationUnclampedButNinetyDaysAQuery() {
        store.insertAll(List.of(row(acme, now.minusSeconds(1)).requestId("customer").build(),
                row(acme, now.minusSeconds(2)).visibility(AuditVisibility.INTERNAL).event("api.request")
                        .category("PLATFORM").requestId("internal").build(),
                read(acme, now.minusSeconds(3)).requestId("read").build(),
                row(globex, now.minusSeconds(4)).requestId("globex").build(),
                row(acme, now.minus(Duration.ofDays(100))).requestId("old").build()));
        asSuperAdmin(sam, null);

        assertThat(platform(f -> { }, null)).containsExactly("customer", "internal", "read", "globex");
        assertThat(platform(f -> f.setVisibility("INTERNAL"), acme)).containsExactly("internal");
        assertThat(platform(f -> f.setVisibility("CUSTOMER"), acme)).containsExactly("customer", "read");
        assertThat(platform(f -> {
            f.setFrom(OffsetDateTime.ofInstant(now.minus(Duration.ofDays(120)), ZoneOffset.UTC));
            f.setTo(OffsetDateTime.ofInstant(now.minus(Duration.ofDays(31)), ZoneOffset.UTC));
        }, acme)).as("older than the customers' window").containsExactly("old");
        assertThatThrownBy(() -> platform(f -> f.setFrom(OffsetDateTime.ofInstant(now.minus(Duration.ofDays(120)),
                ZoneOffset.UTC)), acme)).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> platform(f -> {
            f.setRequestId("customer");
            f.setFrom(OffsetDateTime.ofInstant(now.minus(Duration.ofDays(8)), ZoneOffset.UTC));
        }, null)).isInstanceOf(BadRequestException.class);
        assertThat(platform(f -> f.setRequestId("customer"), null)).containsExactly("customer");
    }

    @Test
    void aSupportReadIsAStaffRowInTheOrganizationsTrailThatTheCustomerReadsAsCertPingSupport() {
        asSuperAdmin(sam, null);
        AuditedReads reads = staffReads();

        reads.staffRead(AuditEventType.SUPPORT_AUDIT_LOG_VIEWED, acme);
        reads.staffRead(AuditEventType.SUPPORT_AUDIT_LOG_VIEWED, acme);
        reads.staffRead(AuditEventType.SUPPORT_AUDIT_LOG_VIEWED, null);
        assertThat(reads.staffExport(AuditEventType.SUPPORT_AUDIT_LOG_EXPORTED, acme,
                AuditSubject.builder().count(3).format("CSV").build())).isTrue();
        // Exports are never grouped: a second one a moment later is a row of its own.
        assertThat(reads.staffExport(AuditEventType.SUPPORT_AUDIT_LOG_EXPORTED, acme,
                AuditSubject.builder().count(5).format("JSON").build())).isTrue();
        assertThat(jdbc.queryForList("SELECT summary FROM audit_events WHERE event = 'support.audit_log_exported' "
                + "AND organization_id = ? ORDER BY id", String.class, acme))
                .containsExactly("Exported 3 audit log entries as CSV", "Exported 5 audit log entries as JSON");

        org.mockito.ArgumentCaptor<AuditEventRow> queued = org.mockito.ArgumentCaptor.forClass(AuditEventRow.class);
        verify(asyncWriter, times(2)).enqueue(queued.capture());
        AuditEventRow viewed = queued.getAllValues().get(0);
        assertThat(viewed.organizationId()).isEqualTo(acme);
        assertThat(viewed.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(viewed.actorStaff()).isTrue();
        assertThat(queued.getAllValues().get(1).visibility()).as("every organization's: internal")
                .isEqualTo(AuditVisibility.INTERNAL);

        // The export's row was written now, durably; the customer reads it as Platform administrator.
        asMember(alice, acme);
        AuditEventEntryDto exported = reader.read(new AuditEventFilterRequest(), null, 20, false, customer())
                .content().get(1);
        assertThat(exported.event()).isEqualTo("support.audit_log_exported");
        assertThat(exported.summary()).isEqualTo("Exported 3 audit log entries as CSV");
        assertThat(exported.actorName()).isEqualTo("Platform administrator");
        assertThat(exported.userId()).isNull();
        assertThat(exported.ipAddress()).isNull();
        assertThat(exported.userAgent()).isNull();

        AuditPlatformEntryDto seen = reader.readPlatform(new AuditPlatformFilterRequest(), 20,
                policy.viewer(true, acme)).content().get(0);
        assertThat(seen.entry().actorName()).isEqualTo("Sam Support");
        assertThat(seen.entry().userId()).isEqualTo(sam);
        assertThat(seen.staff()).isTrue();
        assertThat(seen.actor()).isEqualTo("user:" + sam);
    }

    // ── Plans ────────────────────────────────────────────────────────────

    @Test
    void thePlatformQueryHasNoVisibilityLiteralAndIsServedByTheOrganizationAndTimeIndexes() {
        List<AuditEventRow> rows = new ArrayList<>();
        IntStream.range(0, 2000).forEach(i -> rows.add(row(globex, now.minusSeconds(i)).build()));
        IntStream.range(0, 20).forEach(i -> rows.add(row(acme, now.minusSeconds(i)).build()));
        store.insertAll(rows);
        jdbc.execute("ANALYZE audit_events");
        AuditEventQuery oneOrganization = AuditEventQuery.builder().view(AuditTrailView.PLATFORM).superAdmin(true)
                .organizationId(acme).from(now.minus(Duration.ofDays(90))).to(now).build();
        AuditEventQuery everyOrganization = oneOrganization.toBuilder().organizationId(null).build();

        AuditEventQueryStore.Statement withOrganization = AuditEventQueryStore.listStatement(oneOrganization, null, 0, 21);
        AuditEventQueryStore.Statement withoutOrganization =
                AuditEventQueryStore.listStatement(everyOrganization, null, 0, 21);

        assertThat(whereOf(withOrganization.sql())).doesNotContain("visibility");
        assertThat(whereOf(withoutOrganization.sql())).doesNotContain("visibility");
        String organizationPlan = genericPlan(withOrganization.sql(), withOrganization.params());
        String timePlan = genericPlan(withoutOrganization.sql(), withoutOrganization.params());
        assertThat(usesAny(organizationPlan, partitionIndexes("audit_events_org_idx"))).as(organizationPlan).isTrue();
        assertThat(usesAny(timePlan, partitionIndexes("audit_events_occurred_idx"))).as(timePlan).isTrue();
        assertThat(timePlan).as(timePlan).doesNotContain("Seq Scan");
    }

    @Test
    void referenceIdSearchesAcrossEveryOrganizationUseTheReferenceIdIndexesIncludingOnNewMonths() {
        String created = jdbc.queryForObject("SELECT audit_events_create_partition(now() + interval '5 months')",
                String.class);
        List<String> attached = jdbc.queryForList("SELECT c.relname FROM pg_inherits i JOIN pg_class c "
                + "ON c.oid = i.inhrelid WHERE i.inhparent IN "
                + "('audit_events_request_idx'::regclass, 'audit_events_correlation_idx'::regclass) "
                + "AND c.relname LIKE ?", String.class, created + "%");
        assertThat(created).isNotNull();
        assertThat(attached).as("a month created later inherits both indexes").hasSize(2);

        List<AuditEventRow> rows = new ArrayList<>();
        // Enough rows that walking the time index for one id costs more than the id's index, as in production.
        IntStream.range(0, 20_000).forEach(i -> rows.add(row(i % 2 == 0 ? acme : globex, now.minusSeconds(i))
                .requestId("req-" + i).correlationId(i % 3 == 0 ? "corr-" + i : null).build()));
        store.insertAll(rows);
        jdbc.execute("ANALYZE audit_events");
        AuditEventQuery byRequest = AuditEventQuery.builder().view(AuditTrailView.PLATFORM).superAdmin(true)
                .requestId("req-7").from(now.minus(Duration.ofDays(7))).to(now).build();
        AuditEventQuery byCorrelation = byRequest.toBuilder().requestId(null).correlationId("corr-9").build();

        AuditEventQueryStore.Statement request = AuditEventQueryStore.listStatement(byRequest, null, 0, 21);
        AuditEventQueryStore.Statement correlation = AuditEventQueryStore.listStatement(byCorrelation, null, 0, 21);
        String requestPlan = genericPlan(request.sql(), request.params());
        String correlationPlan = genericPlan(correlation.sql(), correlation.params());

        assertThat(usesAny(requestPlan, partitionIndexes("audit_events_request_idx"))).as(requestPlan).isTrue();
        assertThat(usesAny(correlationPlan, partitionIndexes("audit_events_correlation_idx"))).as(correlationPlan)
                .isTrue();
        assertThat(platform(f -> f.setRequestId("req-7"), null)).containsExactly("req-7");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private AuditTrailExporter exporter(int maxRows, int perHour) {
        return new AuditTrailExporter(reader, queries, store, staffReads(), JsonMapper.builderWithJackson2Defaults()
                .findAndAddModules()
                .build(),
                Clock.systemUTC(), transactionManager, maxRows, perHour, 4);
    }

    private AuditedReads staffReads() {
        return new AuditedReads(new AuditRecorder(store, asyncWriter, transactionManager, dataSource),
                Clock.systemUTC());
    }

    private static String body(AuditTrailExporter.AuditExport export) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        export.body().writeTo(out);
        return out.toString(StandardCharsets.UTF_8);
    }

    private List<String> platform(Consumer<AuditPlatformFilterRequest> setUp, Long organizationId) {
        AuditPlatformFilterRequest filter = new AuditPlatformFilterRequest();
        setUp.accept(filter);
        return reader.readPlatform(filter, 20, policy.viewer(true, organizationId)).content().stream()
                .map(e -> e.entry().requestId()).toList();
    }

    private AuditVisibilityPolicy.Viewer customer() {
        return policy.viewer(false, acme);
    }

    private static void asMember(int userId, long organizationId) {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.set(userId, String.valueOf(organizationId), "req-test", null);
    }

    private static void asSuperAdmin(int userId, Long organizationId) {
        GatewayRequestContext.set(userId, organizationId == null ? null : String.valueOf(organizationId), "req-admin",
                null);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "sam", null, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
    }

    private static String whereOf(String sql) {
        return sql.substring(sql.indexOf(" WHERE "));
    }

    private Set<String> partitionIndexes(String parent) {
        Set<String> indexes = new HashSet<>(jdbc.queryForList("SELECT c.relname FROM pg_inherits i "
                + "JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = ?::regclass", String.class, parent));
        assertThat(indexes).as(parent).isNotEmpty();
        return indexes;
    }

    private static boolean usesAny(String plan, Set<String> indexes) {
        return indexes.stream().anyMatch(index ->
                java.util.regex.Pattern.compile("\\b" + java.util.regex.Pattern.quote(index) + "\\b").matcher(plan).find());
    }

    /** EXPLAIN of {@code sql} as a prepared statement under a forced generic plan. */
    private String genericPlan(String sql, MapSqlParameterSource params) {
        ParsedSql parsed = NamedParameterUtils.parseSqlStatement(sql);
        String positional = NamedParameterUtils.substituteNamedParameters(parsed, params);
        Object[] values = NamedParameterUtils.buildValueArray(parsed, params, null);
        StringBuilder numbered = new StringBuilder();
        int n = 0;
        for (char c : positional.toCharArray()) {
            numbered.append(c == '?' ? "$" + (++n) : String.valueOf(c));
        }
        List<String> literals = new ArrayList<>();
        for (Object value : values) {
            Object v = value instanceof org.springframework.jdbc.core.SqlParameterValue p ? p.getValue() : value;
            literals.add(v instanceof Number ? v.toString() : "'" + String.valueOf(v).replace("'", "''") + "'");
        }
        return new TransactionTemplate(transactionManager).execute(status -> jdbc.execute((ConnectionCallback<String>) c -> {
            try (Statement s = c.createStatement()) {
                s.execute("SET LOCAL plan_cache_mode = force_generic_plan");
                // An index that serves the query is chosen over a scan; with none, the plan still shows "Seq Scan".
                s.execute("SET LOCAL enable_seqscan = off");
                s.execute("PREPARE platform_plan AS " + numbered);
                StringBuilder plan = new StringBuilder();
                try (ResultSet rs = s.executeQuery("EXPLAIN EXECUTE platform_plan(" + String.join(", ", literals) + ")")) {
                    while (rs.next()) {
                        plan.append(rs.getString(1)).append('\n');
                    }
                }
                s.execute("DEALLOCATE platform_plan");
                return plan.toString();
            }
        }));
    }

    private AuditEventRow.AuditEventRowBuilder row(long organizationId, Instant at) {
        return AuditEventRow.builder()
                .occurredAt(at)
                .visibility(AuditVisibility.CUSTOMER)
                .event("organization.updated")
                .category("ORGANIZATION")
                .organizationId(organizationId)
                .actorType(AuditActorType.USER)
                .actorUserId(alice)
                .actorLabel("Alice Admin")
                .action("UPDATE")
                .resourceType("ORGANIZATION")
                .outcome(AuditOutcome.SUCCESS)
                .summary("Changed the organization's settings");
    }

    private AuditEventRow.AuditEventRowBuilder read(long organizationId, Instant at) {
        return row(organizationId, at).event("access.audit_log_viewed").category("ACCESS").action("VIEW")
                .resourceType("AUDIT").summary("Viewed the audit log");
    }
}
