// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The audit_events schema on PostgreSQL 15: the
 * append-only guarantees, the one GDPR exception, and the partition functions, through plain JDBC.
 */
@Testcontainers(disabledWithoutDocker = true)
class AuditEventsSchemaPostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

    private static final DateTimeFormatter SUFFIX = DateTimeFormatter.ofPattern("yyyy_MM");

    @BeforeAll
    static void migrate() {
        flyway().migrate();
    }

    @Test
    void createsAPartitionedTableWithTwelveMonthsBackAndThreeAheadAndADefault() throws SQLException {
        YearMonth now = YearMonth.now(ZoneOffset.UTC);
        List<String> expected = new ArrayList<>();
        for (int m = -12; m <= 3; m++) {
            expected.add("audit_events_" + now.plusMonths(m).format(SUFFIX));
        }
        expected.add("audit_events_default");

        assertThat(strings("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
                + "WHERE i.inhparent = 'audit_events'::regclass")).containsAll(expected);
        assertThat(string("SELECT relkind FROM pg_class WHERE relname = 'audit_events'")).isEqualTo("p");
        assertThat(string("SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conrelid = 'audit_events'::regclass"))
                .isEqualTo("0");
    }

    @Test
    void seedsTheRetentionSettingAndTheRetentionKillSwitch() throws SQLException {
        assertThat(string("SELECT value FROM global_settings WHERE key = 'audit_retention_months'")).isEqualTo("12");
        assertThat(string("SELECT scope || ' ' || category || ' ' || enabled FROM global_feature_flags "
                + "WHERE feature_key = 'AUDIT_RETENTION_PURGE'")).isEqualTo("PLATFORM PLATFORM true");
    }

    @Test
    void anInsertThroughTheParentGetsAnIdAndLandsInItsMonth() throws SQLException {
        long id = insertRow("insert-lands", "now()");

        assertThat(string("SELECT tableoid::regclass::text FROM audit_events WHERE id = " + id))
                .isEqualTo("audit_events_" + YearMonth.now(ZoneOffset.UTC).format(SUFFIX));
    }

    @Test
    void refusesUpdateDeleteAndTruncate() throws SQLException {
        long id = insertRow("refuses", "now()");
        String partition = "audit_events_" + YearMonth.now(ZoneOffset.UTC).format(SUFFIX);

        assertRefused("UPDATE audit_events SET summary = 'rewritten' WHERE id = " + id);
        assertRefused("UPDATE audit_events SET actor_label = 'Former member' WHERE id = " + id);
        assertRefused("DELETE FROM audit_events WHERE id = " + id);
        assertRefused("DELETE FROM " + partition + " WHERE id = " + id);
        assertRefused("TRUNCATE audit_events");
        assertRefused("TRUNCATE " + partition);
        assertRefused("TRUNCATE audit_events_default");
        assertThat(string("SELECT summary FROM audit_events WHERE id = " + id)).isEqualTo("Did refuses");
    }

    @Test
    void anErasureMayPseudonymiseTheActorLabelAndNothingElse() throws SQLException {
        long id = insertRow("erasure", "now()");
        String erasing = "SELECT set_config('certping.audit_erasure', 'on', true); ";

        // Another label, or any other column, stays refused even while erasing.
        assertRefusedInTransaction(erasing + "UPDATE audit_events SET actor_label = 'Somebody else' WHERE id = " + id);
        assertRefusedInTransaction(erasing
                + "UPDATE audit_events SET actor_label = 'Former member', ip_address = NULL WHERE id = " + id);
        assertRefusedInTransaction(erasing + "UPDATE audit_events SET occurred_at = occurred_at - interval '40 days' "
                + "WHERE id = " + id);
        assertRefusedInTransaction(erasing + "DELETE FROM audit_events WHERE id = " + id);

        inTransaction(erasing + "UPDATE audit_events SET actor_label = 'Former member' WHERE id = " + id);

        assertThat(string("SELECT actor_label || ' ' || ip_address || ' ' || summary FROM audit_events WHERE id = " + id))
                .isEqualTo("Former member 203.0.113.9 Did erasure");
        // The setting was transaction-local: the next transaction is append-only again.
        assertRefused("UPDATE audit_events SET actor_label = 'Former member' WHERE id = " + id);
    }

    @Test
    void customerRowsNeedAnEventAndACategory() {
        assertThatThrownBy(() -> execute("INSERT INTO audit_events (occurred_at, visibility, actor_type, action, "
                + "resource_type, outcome, summary) VALUES (now(), 'CUSTOMER', 'USER', 'CREATE', 'USER', 'SUCCESS', 'x')"))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("audit_events_customer_event_check");
    }

    @Test
    void createPartitionIsIdempotentAndTheNewMonthIsGuardedAndIndexed() throws SQLException {
        String month = "2041-03-15T00:00:00Z";

        assertThat(string("SELECT audit_events_create_partition('" + month + "')")).isEqualTo("audit_events_2041_03");
        assertThat(string("SELECT audit_events_create_partition('" + month + "')")).isNull();

        // Rendered in the session's time zone on both sides, so the JVM's zone does not matter.
        assertThat(string("SELECT pg_get_expr(relpartbound, oid) = format('FOR VALUES FROM (%L) TO (%L)', "
                + "'2041-03-01T00:00:00Z'::timestamptz, '2041-04-01T00:00:00Z'::timestamptz) "
                + "FROM pg_class WHERE relname = 'audit_events_2041_03'")).isEqualTo("t");
        assertThat(strings("SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_events_2041_03'::regclass"))
                .contains("audit_events_append_only", "audit_events_2041_03_no_truncate");
        assertThat(strings("SELECT conname FROM pg_constraint WHERE conrelid = 'audit_events_2041_03'::regclass"))
                .doesNotContain("audit_events_2041_03_bounds");
        assertThat(string("SELECT count(*) FROM pg_indexes WHERE tablename = 'audit_events_2041_03'"))
                .isEqualTo(string("SELECT count(*) FROM pg_indexes WHERE tablename = 'audit_events_default'"));

        long id = insertRow("future", "'2041-03-20T10:00:00Z'");
        assertThat(string("SELECT tableoid::regclass::text FROM audit_events WHERE id = " + id))
                .isEqualTo("audit_events_2041_03");
        assertRefused("TRUNCATE audit_events_2041_03");
    }

    @Test
    void dropPartitionsBeforeDropsOnlyWholeMonthsBeforeTheCutoffAndRefusesARecentOne() throws SQLException {
        execute("SELECT audit_events_create_partition('2019-01-10T00:00:00Z')");
        execute("SELECT audit_events_create_partition('2019-02-10T00:00:00Z')");
        insertRow("old", "'2019-01-20T00:00:00Z'");

        assertThat(strings("SELECT audit_events_drop_partitions_before('2019-02-01T00:00:00Z')"))
                .containsExactly("audit_events_2019_01");
        assertThat(string("SELECT to_regclass('audit_events_2019_01')")).isNull();
        assertThat(string("SELECT to_regclass('audit_events_2019_02')")).isEqualTo("audit_events_2019_02");

        assertThatThrownBy(() -> execute("SELECT audit_events_drop_partitions_before(now())"))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("later than six months ago");
        assertThat(string("SELECT to_regclass('audit_events_" + YearMonth.now(ZoneOffset.UTC).format(SUFFIX) + "')"))
                .isNotNull();
    }

    private static long insertRow(String marker, String occurredAt) throws SQLException {
        return Long.parseLong(string("INSERT INTO audit_events (occurred_at, visibility, event, category, actor_type, "
                + "actor_user_id, actor_label, action, resource_type, outcome, summary, ip_address) VALUES ("
                + occurredAt + ", 'CUSTOMER', 'member.created', 'ACCESS_CONTROL', 'USER', 7, 'Alice', 'USER_CREATED', "
                + "'USER', 'SUCCESS', 'Did " + marker + "', '203.0.113.9') RETURNING id"));
    }

    private static void assertRefused(String sql) {
        assertThatThrownBy(() -> execute(sql))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("audit_events is append-only");
    }

    private static void assertRefusedInTransaction(String sql) {
        assertThatThrownBy(() -> inTransaction(sql))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining("audit_events is append-only");
    }

    private static void inTransaction(String sql) throws SQLException {
        try (Connection c = connect()) {
            c.setAutoCommit(false);
            try (Statement s = c.createStatement()) {
                s.execute(sql);
                c.commit();
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        }
    }

    private static void execute(String sql) throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }

    private static String string(String sql) throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            assertThat(rs.next()).isTrue();
            return rs.getString(1);
        }
    }

    private static List<String> strings(String sql) throws SQLException {
        List<String> values = new ArrayList<>();
        try (Connection c = connect(); Statement s = c.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            while (rs.next()) {
                values.add(rs.getString(1));
            }
        }
        return values;
    }

    private static Flyway flyway() {
        return Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load();
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }
}
