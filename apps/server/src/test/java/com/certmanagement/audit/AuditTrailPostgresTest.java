// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditEventEntryDto;
import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.dto.audit.AuditEventPageResponse;
import com.certmanagement.service.FeatureFlagService;
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
import org.springframework.dao.QueryTimeoutException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterUtils;
import org.springframework.jdbc.core.namedparam.ParsedSql;
import org.springframework.jdbc.datasource.DelegatingDataSource;
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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
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
import java.util.function.Consumer;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;

/**
 * The read API's SQL on PostgreSQL 15: the window, keyset paging over
 * equal timestamps, the filters, read-time names, the count's timeout fallback behind a savepoint, a
 * timed-out list as Spring's QueryTimeoutException, and the generic plan using the partial customer
 * index because the visibility is a literal.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.count-timeout-ms=1000", "certping.audit.list-timeout-ms=1000"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditEventStore.class, AuditEventQueryStore.class, AuditTrailReader.class, AuditVisibilityPolicy.class,
        AuditTrailPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditTrailPostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

    /** Which statement the proxy slows down with pg_sleep(2), to force a timeout. */
    enum Slow { NONE, COUNT, LIST, LOOKUP }

    static volatile Slow slow = Slow.NONE;

    @TestConfiguration
    static class Beans {
        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }

        @Bean
        static BeanPostProcessor slowingDataSource() {
            return new BeanPostProcessor() {
                @Override
                public Object postProcessAfterInitialization(Object bean, String name) throws BeansException {
                    return bean instanceof DataSource dataSource && !(bean instanceof SlowingDataSource)
                            ? new SlowingDataSource(dataSource) : bean;
                }
            };
        }
    }

    /** Rewrites the audit count or list to sleep first, while {@link #slow} says so. */
    static final class SlowingDataSource extends DelegatingDataSource {
        SlowingDataSource(DataSource target) {
            super(target);
        }

        @Override
        public Connection getConnection() throws SQLException {
            return slowing(super.getConnection());
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return slowing(super.getConnection(username, password));
        }

        private static Connection slowing(Connection target) {
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                    new Class<?>[]{Connection.class}, (proxy, method, args) -> {
                        if (method.getName().equals("prepareStatement") && args != null && args[0] instanceof String sql) {
                            args[0] = rewrite(sql);
                        }
                        try {
                            return method.invoke(target, args);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    });
        }

        private static String rewrite(String sql) {
            return switch (slow) {
                case COUNT -> sql.replace("SELECT 1 FROM audit_events", "SELECT 1 FROM pg_sleep(2), audit_events");
                case LIST -> sql.startsWith("SELECT id,")
                        ? sql.replace("FROM audit_events WHERE", "FROM pg_sleep(2), audit_events WHERE") : sql;
                case LOOKUP -> sql.replace("FROM users u WHERE", "FROM pg_sleep(2), users u WHERE");
                case NONE -> sql;
            };
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

    private final Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
    private long acme;
    private long globex;
    private int alice;
    private int bob;

    @BeforeEach
    void seed() {
        slow = Slow.NONE;
        when(featureFlags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        YearMonth month = YearMonth.now(ZoneOffset.UTC);
        for (int back = -5; back <= 1; back++) {
            store.createPartition(month.plusMonths(back));
        }
        jdbc.execute("DELETE FROM user_roles");
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
        acme = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id", Long.class);
        globex = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Globex', 'globex.test', 'globex') RETURNING id",
                Long.class);
        alice = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('alice@acme.test', 'Alice Admin', ?) RETURNING id", Integer.class, acme);
        bob = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('bob@acme.test', 'Bob Builder', ?) RETURNING id", Integer.class, acme);
    }

    @AfterEach
    void fast() {
        slow = Slow.NONE;
    }

    // ── Paging ───────────────────────────────────────────────────────────

    @Test
    void cursorPagesAreStableAcrossRowsWithTheSameTimestampAndNewRows() {
        Instant same = now.minus(Duration.ofHours(1));
        List<AuditEventRow> rows = new ArrayList<>();
        IntStream.range(0, 25).forEach(i -> rows.add(row(acme, same).build()));
        IntStream.range(0, 5).forEach(i -> rows.add(row(globex, same).build()));
        store.insertAll(rows);
        List<Long> expected = jdbc.queryForList("SELECT id FROM audit_events WHERE organization_id = ? "
                + "ORDER BY id DESC", Long.class, acme);

        AuditEventPageResponse first = read(customer(), f -> { }, 10);
        // A newer row arriving between pages does not shift the pages after the first.
        store.insert(row(acme, now).build());
        AuditEventPageResponse second = read(customer(), f -> f.setCursor(first.nextCursor()), 10);
        AuditEventPageResponse third = read(customer(), f -> f.setCursor(second.nextCursor()), 10);

        List<Long> seen = new ArrayList<>();
        for (AuditEventPageResponse page : List.of(first, second, third)) {
            page.content().forEach(e -> seen.add(e.id()));
        }
        assertThat(seen).containsExactlyElementsOf(expected);
        assertThat(new HashSet<>(seen)).hasSize(25);
        assertThat(first.totalElements()).isEqualTo(25);
        assertThat(third.totalElements()).as("counted once, carried in the cursor").isEqualTo(25);
        assertThat(List.of(first.number(), second.number(), third.number())).containsExactly(0, 1, 2);
        assertThat(third.last()).isTrue();
        assertThat(third.nextCursor()).isNull();
        assertThat(third.content()).hasSize(5);
    }

    @Test
    void ascendingCursorPagesRunOldestFirst() {
        Instant same = now.minus(Duration.ofHours(1));
        store.insertAll(IntStream.range(0, 7).mapToObj(i -> row(acme, same.plusSeconds(i % 3)).build()).toList());

        AuditEventPageResponse first = reader.read(filter(f -> { }), null, 4, true, customer());
        AuditEventPageResponse second = reader.read(filter(f -> f.setCursor(first.nextCursor())), null, 4, false,
                customer());

        List<AuditEventEntryDto> all = new ArrayList<>(first.content());
        all.addAll(second.content());
        assertThat(all).hasSize(7);
        for (int i = 1; i < all.size(); i++) {
            AuditEventEntryDto previous = all.get(i - 1);
            AuditEventEntryDto current = all.get(i);
            assertThat(previous.timestamp().isBefore(current.timestamp())
                    || previous.timestamp().isEqual(current.timestamp()) && previous.id() < current.id()).isTrue();
        }
    }

    @Test
    void anOffsetPageStillWorksForTheOldPage() {
        store.insertAll(IntStream.range(0, 7).mapToObj(i -> row(acme, now.minusSeconds(i)).build()).toList());

        AuditEventPageResponse page = reader.read(filter(f -> { }), 1, 3, false, customer());

        assertThat(page.number()).isEqualTo(1);
        assertThat(page.content()).hasSize(3);
        assertThat(page.totalElements()).isEqualTo(7);
        assertThat(page.totalPages()).isEqualTo(3);
        assertThat(page.last()).isFalse();
        AuditEventPageResponse next = read(customer(), f -> f.setCursor(page.nextCursor()), 3);
        assertThat(next.number()).isEqualTo(2);
        assertThat(next.content()).hasSize(1);
    }

    // ── Window and visibility ────────────────────────────────────────────

    @Test
    void customersSeeNinetyDaysAndSuperAdminsTheWholeTrail() {
        store.insertAll(List.of(row(acme, now.minus(Duration.ofDays(100))).requestId("old").build(),
                row(acme, now.minus(Duration.ofDays(10))).requestId("recent").build()));
        OffsetDateTime longAgo = OffsetDateTime.ofInstant(now.minus(Duration.ofDays(400)), ZoneOffset.UTC);

        AuditEventPageResponse customer = read(customer(), f -> f.setFrom(longAgo), 20);
        AuditEventPageResponse superAdmin = read(policy.viewer(true, acme), f -> f.setFrom(longAgo), 20);

        assertThat(customer.content()).extracting(AuditEventEntryDto::requestId).containsExactly("recent");
        assertThat(customer.visibleFrom()).isNotNull();
        assertThat(superAdmin.content()).extracting(AuditEventEntryDto::requestId).containsExactly("recent", "old");
        assertThat(superAdmin.visibleFrom()).isNull();
    }

    @Test
    void internalRowsAndOtherOrganizationsAreNeverListedToACustomer() {
        store.insertAll(List.of(row(acme, now).requestId("mine").build(),
                row(globex, now).requestId("theirs").build(),
                row(acme, now).visibility(AuditVisibility.INTERNAL).event("api.request").category("PLATFORM")
                        .requestId("internal").build()));

        assertThat(read(customer(), f -> { }, 20).content()).extracting(AuditEventEntryDto::requestId)
                .containsExactly("mine");
        assertThat(read(policy.viewer(true, null), f -> { }, 20).content()).extracting(AuditEventEntryDto::requestId)
                .containsExactlyInAnyOrder("mine", "theirs");
    }

    // ── Filters ──────────────────────────────────────────────────────────

    @Test
    void theFiltersNarrowInSql() {
        store.insertAll(List.of(
                row(acme, now.minusSeconds(1)).requestId("signin").event("auth.signed_in").category("AUTHENTICATION")
                        .action("SIGN_IN").resourceType("AUTH").build(),
                row(acme, now.minusSeconds(2)).requestId("system").actorType(AuditActorType.SYSTEM).actorUserId(null)
                        .actorLabel("CertPing (automatic)").correlationId("corr-9").build(),
                row(acme, now.minusSeconds(3)).requestId("failed").outcome(AuditOutcome.FAILURE)
                        .errorCode("PERMISSION_DENIED").resourceName("Prod-DNS").resourceRef("cred_1").build(),
                row(acme, now.minusSeconds(4)).requestId("bob").actorUserId(bob).actorLabel("Bob Builder").build()));

        assertThat(requestIds(f -> f.setActorType("SYSTEM"))).containsExactly("system");
        assertThat(requestIds(f -> f.setRequestId("failed"))).containsExactly("failed");
        assertThat(requestIds(f -> f.setCorrelationId("corr-9"))).containsExactly("system");
        assertThat(requestIds(f -> f.setStatus("FAILURE"))).containsExactly("failed");
        assertThat(requestIds(f -> f.setCategory("AUTHENTICATION"))).containsExactly("signin");
        assertThat(requestIds(f -> f.setResourceName("prod-dns"))).containsExactly("failed");
        assertThat(requestIds(f -> f.setResourceRef("cred_1"))).containsExactly("failed");
        assertThat(requestIds(f -> f.setUserId(bob))).containsExactly("bob");
        assertThat(requestIds(f -> f.setEvent("auth.signed_in"))).containsExactly("signin");
    }

    @Test
    void sensitiveReadsAreLeftOutOfTheListUnlessAskedForByCategory() {
        store.insertAll(List.of(row(acme, now.minusSeconds(1)).requestId("change").build(),
                row(acme, now.minusSeconds(2)).requestId("read").event("access.audit_log_viewed").category("ACCESS")
                        .action("VIEW").resourceType("AUDIT").summary("Viewed the audit log").build()));

        assertThat(requestIds(f -> { })).containsExactly("change");
        assertThat(requestIds(f -> f.setEvent("access.audit_log_viewed"))).as("not without the category").isEmpty();
        assertThat(requestIds(f -> f.setCategory("ACCESS"))).containsExactly("read");
        assertThat(read(customer(), f -> { }, 20).totalElements()).isEqualTo(1);
        assertThat(read(policy.viewer(true, null), f -> { }, 20).content()).extracting(AuditEventEntryDto::requestId)
                .containsExactly("change");
    }

    @Test
    void featureOffKeysHideRowsOnlyWhenThePolicySaysSo() {
        store.insertAll(List.of(row(acme, now).requestId("cred").event("credential.deleted").category("CREDENTIALS")
                        .featureKey("CREDENTIALS_MANAGEMENT").build(),
                row(acme, now).requestId("core").build()));
        AuditEventQuery all = AuditEventQuery.builder().organizationId(acme).build();

        assertThat(queries.list(all, null, 0, 10)).hasSize(2);
        assertThat(queries.list(all.toBuilder().hiddenFeatureKeys(Set.of("CREDENTIALS_MANAGEMENT")).build(), null, 0, 10))
                .extracting(AuditEventRecord::requestId).containsExactly("core");
    }

    // ── Read-time names ──────────────────────────────────────────────────

    @Test
    void namesAreRenderedFromTheLiveRowsAtReadTime() {
        store.insertAll(List.of(
                row(acme, now.minusSeconds(1)).event("member.created").action("USER_CREATED").resourceType("USER")
                        .resourceId((long) bob).resourceRef(String.valueOf(bob)).summary("Added a member").build(),
                row(acme, now.minusSeconds(2)).event("member.deleted").action("USER_DELETED").resourceType("USER")
                        .resourceId(999_999L).resourceRef("999999").summary("Removed a member").build()));
        jdbc.update("UPDATE users SET display_name = 'Robert Builder' WHERE id = ?", bob);

        List<AuditEventEntryDto> entries = read(customer(), f -> { }, 20).content();

        assertThat(entries).extracting(AuditEventEntryDto::summary)
                .containsExactly("Added Robert Builder", "Removed a former member");
        assertThat(entries.get(0).userEmail()).isEqualTo("alice@acme.test");
        assertThat(entries.get(0).actorName()).isEqualTo("Alice Admin");
        assertThat(entries.get(0).organizationName()).isEqualTo("Acme");

        jdbc.update("UPDATE users SET is_deleted = true WHERE id = ?", bob);
        jdbc.update("UPDATE organizations SET is_deleted = true WHERE id = ?", acme);
        List<AuditEventEntryDto> later = read(customer(), f -> { }, 20).content();
        assertThat(later.get(0).summary()).isEqualTo("Added a former member");
        assertThat(later.get(0).organizationName()).isEqualTo("Deleted organization");
        assertThat(read(policy.viewer(true, acme), f -> { }, 20).content().get(0).organizationName())
                .isEqualTo("Deleted organization (#" + acme + ")");
    }

    @Test
    void theRequesterOfASystemRowIsReadFromTheLiveUsersRow() {
        int staff = jdbc.queryForObject("INSERT INTO users (email, display_name) VALUES ('sam@example.com', 'Sam') "
                + "RETURNING id", Integer.class);
        jdbc.update("INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles WHERE name = 'SUPER_ADMIN' "
                + "AND organization_id IS NULL", staff);
        store.insertAll(List.of(
                row(acme, now.minusSeconds(1)).requestId("bob").actorType(AuditActorType.SYSTEM).actorUserId(null)
                        .actorLabel(null).details(new AuditDetails(List.of(), java.util.Map.of("requestedBy",
                                String.valueOf(bob)))).build(),
                row(acme, now.minusSeconds(2)).requestId("staff").actorType(AuditActorType.SYSTEM).actorUserId(null)
                        .actorLabel(null).details(new AuditDetails(List.of(), java.util.Map.of("requestedBy",
                                String.valueOf(staff)))).build()));

        List<AuditEventEntryDto> customer = read(customer(), f -> { }, 20).content();
        List<AuditEventEntryDto> platform = read(policy.viewer(true, acme), f -> { }, 20).content();

        assertThat(customer).extracting(AuditEventEntryDto::requestedByName)
                .containsExactly("Bob Builder", "Platform administrator");
        assertThat(customer).as("the raw id stays out of a customer's details").extracting(AuditEventEntryDto::details)
                .containsOnlyNulls();
        assertThat(platform.get(0).details()).contains("\"requestedBy\":\"" + bob + "\"");
        assertThat(platform).extracting(AuditEventEntryDto::requestedByName).containsExactly("Bob Builder", "Sam");

        jdbc.update("UPDATE users SET is_deleted = true WHERE id = ?", bob);
        assertThat(read(customer(), f -> { }, 20).content().get(0).requestedByName()).isEqualTo("a former member");
    }

    // ── Count cap and timeouts ───────────────────────────────────────────

    @Test
    void aCountThatTimesOutFallsBackToALowerBoundAndTheTransactionCarriesOn() {
        store.insertAll(IntStream.range(0, 5).mapToObj(i -> row(acme, now.minusSeconds(i)).build()).toList());
        slow = Slow.COUNT;

        AuditEventPageResponse page = read(customer(), f -> { }, 2);

        assertThat(page.totalElementsCapped()).isTrue();
        assertThat(page.totalElements()).isEqualTo(3);
        assertThat(page.last()).isFalse();
        // The lookups after the cancelled count ran in the same transaction: the savepoint kept it usable.
        assertThat(page.content()).allSatisfy(e -> {
            assertThat(e.userEmail()).isEqualTo("alice@acme.test");
            assertThat(e.organizationName()).isEqualTo("Acme");
        });
    }

    @Test
    void theCountStopsAtTheCap() {
        store.insertAll(IntStream.range(0, 12).mapToObj(i -> row(acme, now.minusSeconds(i)).build()).toList());
        AuditTrailReader capped = new AuditTrailReader(queries, Clock.systemUTC(), 10, 90);

        AuditEventPageResponse page = capped.read(filter(f -> { }), null, 4, false, customer());

        assertThat(page.totalElements()).isEqualTo(10);
        assertThat(page.totalElementsCapped()).isTrue();
        assertThat(page.totalPages()).isEqualTo(3);
        AuditEventPageResponse lastOffsetPage = capped.read(filter(f -> { }), 2, 4, false, customer());
        assertThat(lastOffsetPage.content()).as("rows past the cap are not served by offset").hasSize(2);
        assertThat(lastOffsetPage.last()).isTrue();
        assertThat(lastOffsetPage.nextCursor()).as("the cursor goes on past the cap").isNotNull();
    }

    @Test
    void aListThatOutlastsItsOwnTimeoutIsSpringsQueryTimeoutException() {
        store.insert(row(acme, now).build());
        slow = Slow.LIST;

        // No statement_timeout: the list's own JDBC timeout (list-timeout-ms, 1 s here) cancels it.
        assertThatThrownBy(() -> queries.list(AuditEventQuery.builder().organizationId(acme).build(), null, 0, 10))
                .isInstanceOf(QueryTimeoutException.class);
        assertThatThrownBy(() -> read(customer(), f -> { }, 20)).isInstanceOf(QueryTimeoutException.class);
    }

    @Test
    void aNameLookupThatTimesOutIsSpringsQueryTimeoutExceptionToo() {
        slow = Slow.LOOKUP;

        assertThatThrownBy(() -> queries.users(List.of(alice))).isInstanceOf(QueryTimeoutException.class);
    }

    @Test
    void aCustomerQueryWithoutAnOrganizationIsRefusedBeforeItRuns() {
        assertThatThrownBy(() -> queries.list(AuditEventQuery.builder().build(), null, 0, 10))
                .isInstanceOf(IllegalStateException.class);
        assertThat(queries.list(AuditEventQuery.builder().superAdmin(true).build(), null, 0, 10)).isEmpty();
    }

    // ── Plans ────────────────────────────────────────────────────────────

    @Test
    void theGenericPlanUsesThePartialCustomerIndexBecauseTheVisibilityIsALiteral() {
        List<AuditEventRow> rows = new ArrayList<>();
        IntStream.range(0, 3000).forEach(i -> rows.add(row(acme, now.minusSeconds(i)).visibility(AuditVisibility.INTERNAL)
                .event("api.request").category("PLATFORM").build()));
        IntStream.range(0, 20).forEach(i -> rows.add(row(acme, now.minusSeconds(i)).build()));
        IntStream.range(0, 200).forEach(i -> rows.add(row(globex, now.minusSeconds(i)).build()));
        store.insertAll(rows);
        jdbc.execute("ANALYZE audit_events");
        Set<String> customerIndexes = new HashSet<>(jdbc.queryForList("SELECT c.relname FROM pg_inherits i "
                + "JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'audit_events_customer_idx'::regclass",
                String.class));
        AuditEventQuery query = AuditEventQuery.builder().organizationId(acme)
                .from(now.minus(Duration.ofDays(90))).build();
        AuditEventQueryStore.Statement list = AuditEventQueryStore.listStatement(query, null, 0, 21);

        String literal = genericPlan(list.sql(), list.params());
        String bound = genericPlan(list.sql().replace("visibility = 'CUSTOMER'", "visibility = :visibility"),
                list.params().addValue("visibility", "CUSTOMER"));

        assertThat(customerIndexes).isNotEmpty();
        assertThat(usesAny(literal, customerIndexes)).as(literal).isTrue();
        assertThat(usesAny(bound, customerIndexes)).as("a bound visibility loses the partial index:\n" + bound)
                .isFalse();

        AuditEventQueryStore.Statement keyset = AuditEventQueryStore.listStatement(query,
                new AuditEventQueryStore.Keyset(now, 1), 0, 21);
        String keysetPlan = genericPlan(keyset.sql(), keyset.params());
        assertThat(usesAny(keysetPlan, customerIndexes)).as(keysetPlan).isTrue();
    }

    /** Whether the plan names one of the indexes as a whole word ("x_idx" is not "x_idx1"). */
    private static boolean usesAny(String plan, Set<String> indexes) {
        return indexes.stream().anyMatch(index ->
                java.util.regex.Pattern.compile("\\b" + java.util.regex.Pattern.quote(index) + "\\b").matcher(plan).find());
    }

    /** EXPLAIN of {@code sql} as a prepared statement under a forced generic plan. */
    private String genericPlan(String sql, org.springframework.jdbc.core.namedparam.MapSqlParameterSource params) {
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
                s.execute("SET LOCAL enable_seqscan = off");
                s.execute("PREPARE audit_plan AS " + numbered);
                StringBuilder plan = new StringBuilder();
                try (ResultSet rs = s.executeQuery("EXPLAIN EXECUTE audit_plan(" + String.join(", ", literals) + ")")) {
                    while (rs.next()) {
                        plan.append(rs.getString(1)).append('\n');
                    }
                }
                s.execute("DEALLOCATE audit_plan");
                return plan.toString();
            }
        }));
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private AuditVisibilityPolicy.Viewer customer() {
        return policy.viewer(false, acme);
    }

    private AuditEventPageResponse read(AuditVisibilityPolicy.Viewer viewer, Consumer<AuditEventFilterRequest> setUp,
                                        int size) {
        return reader.read(filter(setUp), null, size, false, viewer);
    }

    private List<String> requestIds(Consumer<AuditEventFilterRequest> setUp) {
        return read(customer(), setUp, 20).content().stream().map(AuditEventEntryDto::requestId).toList();
    }

    private static AuditEventFilterRequest filter(Consumer<AuditEventFilterRequest> setUp) {
        AuditEventFilterRequest filter = new AuditEventFilterRequest();
        setUp.accept(filter);
        return filter;
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
}
