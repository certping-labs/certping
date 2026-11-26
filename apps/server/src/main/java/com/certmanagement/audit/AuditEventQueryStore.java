// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.exception.SqlStates;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Reads the customer trail from {@code audit_events}. Every query spells {@code visibility = 'CUSTOMER'}
 * as a literal, so the partial customer indexes stay usable under generic plans; the
 * organization, the window and the keyset follow the index's {@code (organization_id, occurred_at DESC,
 * id DESC)} order, and the window lets Postgres prune the monthly partitions.
 *
 * <p>The total is counted only up to a cap ({@code certping.audit.count-cap}),
 * with its own timeout ({@code certping.audit.count-timeout-ms}) behind a savepoint, so a slow count
 * degrades to a lower-bound total instead of failing the page or the transaction. The list and the name
 * lookups have their own JDBC timeout ({@code certping.audit.list-timeout-ms}, 10 s), well inside the
 * pool's statement timeout; any query a timeout cancels surfaces as Spring's {@link QueryTimeoutException},
 * which the API answers with a 503 {@code QUERY_TIMEOUT}.
 */
@DependsOnDatabaseInitialization
@Slf4j
@Repository
public class AuditEventQueryStore {

    /** PostgreSQL's "query_canceled": a statement_timeout or a JDBC query timeout. */
    static final String QUERY_CANCELED = "57014";
    /** PostgreSQL's "lock_not_available": a lock_timeout, e.g. waiting for another export's lock. */
    static final String LOCK_NOT_AVAILABLE = "55P03";

    private static final String COLUMNS = """
            id, occurred_at, event, category, feature_key, organization_id, actor_type, actor_user_id,
            actor_label, actor_staff, action, resource_type, resource_id, resource_ref, resource_name, outcome,
            error_code, summary, details::text AS details, ip_address, user_agent, request_id, correlation_id,
            visibility, actor_job, auth_method, trace_id
            """;

    private static final RowMapper<AuditEventRecord> RECORD = (rs, n) -> new AuditEventRecord(
            rs.getLong("id"),
            rs.getObject("occurred_at", OffsetDateTime.class).toInstant(),
            rs.getString("event"),
            rs.getString("category"),
            rs.getString("feature_key"),
            rs.getObject("organization_id", Long.class),
            rs.getString("actor_type"),
            rs.getObject("actor_user_id", Integer.class),
            rs.getString("actor_label"),
            rs.getBoolean("actor_staff"),
            rs.getString("action"),
            rs.getString("resource_type"),
            rs.getObject("resource_id", Long.class),
            rs.getString("resource_ref"),
            rs.getString("resource_name"),
            rs.getString("outcome"),
            rs.getString("error_code"),
            rs.getString("summary"),
            rs.getString("details"),
            rs.getString("ip_address"),
            rs.getString("user_agent"),
            rs.getString("request_id"),
            rs.getString("correlation_id"),
            rs.getString("visibility"),
            rs.getString("actor_job"),
            rs.getString("auth_method"),
            rs.getString("trace_id"));

    /** Rows an export holds in memory at once: the JDBC fetch size, and the size of each rendered chunk. */
    public static final int EXPORT_FETCH_SIZE = 500;

    /** The events an organization's exports are counted by, for the exports-per-hour limit. */
    static final List<String> EXPORT_EVENTS = List.of(AuditEventType.AUDIT_LOG_EXPORTED.key(),
            AuditEventType.ACCESS_LOG_EXPORTED.key());

    private final NamedParameterJdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate countJdbc;
    private final NamedParameterJdbcTemplate exportJdbc;
    private final DataSource dataSource;
    private final int countTimeoutSeconds;
    private final int exportLockTimeoutMillis;

    public AuditEventQueryStore(DataSource dataSource,
                                @Value("${certping.audit.count-timeout-ms:3000}") int countTimeoutMillis,
                                @Value("${certping.audit.list-timeout-ms:10000}") int listTimeoutMillis,
                                @Value("${certping.audit.export-timeout-ms:25000}") int exportTimeoutMillis,
                                @Value("${certping.audit.export-lock-timeout-ms:5000}") int exportLockTimeoutMillis) {
        if (exportLockTimeoutMillis < 1) {
            throw new IllegalArgumentException("certping.audit.export-lock-timeout-ms must be positive, was "
                    + exportLockTimeoutMillis);
        }
        this.dataSource = dataSource;
        this.exportLockTimeoutMillis = exportLockTimeoutMillis;
        this.countTimeoutSeconds = wholeSeconds("certping.audit.count-timeout-ms", countTimeoutMillis);
        this.jdbc = withTimeout(dataSource, wholeSeconds("certping.audit.list-timeout-ms", listTimeoutMillis));
        this.countJdbc = withTimeout(dataSource, countTimeoutSeconds);
        JdbcTemplate export = new JdbcTemplate(dataSource);
        export.setQueryTimeout(wholeSeconds("certping.audit.export-timeout-ms", exportTimeoutMillis));
        // With a fetch size, inside a transaction (auto-commit off), the driver reads the rows through a cursor,
        // EXPORT_FETCH_SIZE at a time, instead of loading every row of the result first.
        export.setFetchSize(EXPORT_FETCH_SIZE);
        this.exportJdbc = new NamedParameterJdbcTemplate(export);
    }

    /** JDBC query timeouts are whole seconds: rounded up so a query never gets less than configured. */
    private static int wholeSeconds(String property, int millis) {
        if (millis < 1000) {
            // Below a second the JDBC timeout would round to 0, which means no timeout at all.
            throw new IllegalArgumentException(property + " must be at least 1000, was " + millis);
        }
        return (int) Math.ceil(millis / 1000.0);
    }

    private static NamedParameterJdbcTemplate withTimeout(DataSource dataSource, int seconds) {
        JdbcTemplate template = new JdbcTemplate(dataSource);
        template.setQueryTimeout(seconds);
        return new NamedParameterJdbcTemplate(template);
    }

    /** Where a keyset page starts: strictly after this row in the query's order. */
    public record Keyset(Instant occurredAt, long id) {
    }

    /**
     * Up to {@code limit} rows in the query's order: after {@code after} when it is set, else from
     * {@code offset}.
     */
    public List<AuditEventRecord> list(AuditEventQuery query, Keyset after, long offset, int limit) {
        Statement statement = listStatement(query, after, offset, limit);
        return translatingTimeouts(() -> jdbc.query(statement.sql(), statement.params(), RECORD));
    }

    /** A statement and its named parameters; package-private so the plan tests can EXPLAIN what runs. */
    record Statement(String sql, MapSqlParameterSource params) {
    }

    static Statement listStatement(AuditEventQuery query, Keyset after, long offset, int limit) {
        MapSqlParameterSource params = new MapSqlParameterSource();
        StringBuilder rows = new StringBuilder("SELECT ").append(COLUMNS).append(" FROM audit_events ")
                .append(where(query, params));
        if (after != null) {
            rows.append(query.ascending() ? " AND (occurred_at, id) > (:afterAt, :afterId)"
                    : " AND (occurred_at, id) < (:afterAt, :afterId)");
            params.addValue("afterAt", utc(after.occurredAt())).addValue("afterId", after.id());
        }
        StringBuilder sql;
        if (searchesAReferenceAcrossOrganizations(query)) {
            // A request or correlation id across every organization: match the id first, through its own index,
            // then order the few rows found. Without the fence a plan, generic ones especially, walks the
            // time index newest first for the LIMIT and filters every row of the range by the id.
            sql = new StringBuilder("WITH matched AS MATERIALIZED (").append(rows).append(") SELECT * FROM matched");
        } else {
            sql = rows;
        }
        sql.append(query.ascending() ? " ORDER BY occurred_at, id" : " ORDER BY occurred_at DESC, id DESC");
        sql.append(" LIMIT :limit");
        params.addValue("limit", limit);
        if (after == null && offset > 0) {
            sql.append(" OFFSET :offset");
            params.addValue("offset", offset);
        }
        return new Statement(sql.toString(), params);
    }

    /** The platform's search by a reference id with no organization named (at most 7 days, the reader's rule). */
    static boolean searchesAReferenceAcrossOrganizations(AuditEventQuery query) {
        return query.organizationId() == null && (query.requestId() != null || query.correlationId() != null);
    }

    static Statement countStatement(AuditEventQuery query, int upTo) {
        MapSqlParameterSource params = new MapSqlParameterSource("upTo", upTo);
        String sql = "SELECT count(*) FROM (SELECT 1 FROM audit_events " + where(query, params)
                + " LIMIT :upTo) AS matching";
        return new Statement(sql, params);
    }

    /**
     * How many rows match, counted up to {@code upTo}; empty when the count timed out. The limit stops
     * the scan of the partial index after {@code upTo} entries, and the timeout bounds a filter the index
     * cannot answer. The count runs behind a savepoint when a transaction is open: PostgreSQL aborts the
     * whole transaction when a statement is cancelled, and the page still has lookups to run.
     */
    public OptionalLong countUpTo(AuditEventQuery query, int upTo) {
        Statement count = countStatement(query, upTo);
        try {
            Long counted = behindSavepoint(() -> translatingTimeouts(
                    () -> countJdbc.queryForObject(count.sql(), count.params(), Long.class)));
            return OptionalLong.of(counted == null ? 0 : counted);
        } catch (QueryTimeoutException timedOut) {
            log.warn("Audit event count timed out after {} s; the page's total is a lower bound", countTimeoutSeconds);
            return OptionalLong.empty();
        }
    }

    /**
     * Streams up to {@code limit} rows in the query's order to {@code chunks}, at most
     * {@value #EXPORT_FETCH_SIZE} at a time: the driver fetches them through a cursor, so an export never holds
     * more than one chunk in memory. Must run in a transaction (a read-only one): outside one, PostgreSQL's
     * driver ignores the fetch size and reads the whole result first.
     *
     * @return how many rows were streamed
     */
    public long stream(AuditEventQuery query, int limit, Consumer<List<AuditEventRecord>> chunks) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("an audit export streams inside a transaction, or its rows are not fetched"
                    + " by cursor");
        }
        Statement statement = listStatement(query, null, 0, limit);
        List<AuditEventRecord> chunk = new ArrayList<>(EXPORT_FETCH_SIZE);
        long[] streamed = {0};
        translatingTimeouts(() -> {
            exportJdbc.query(statement.sql(), statement.params(), (org.springframework.jdbc.core.RowCallbackHandler) rs -> {
                chunk.add(RECORD.mapRow(rs, (int) streamed[0]));
                streamed[0]++;
                if (chunk.size() == EXPORT_FETCH_SIZE) {
                    chunks.accept(List.copyOf(chunk));
                    chunk.clear();
                }
            });
            return null;
        });
        if (!chunk.isEmpty()) {
            chunks.accept(List.copyOf(chunk));
        }
        return streamed[0];
    }

    /**
     * How many rows match, counted up to {@code upTo}, for an export deciding whether it is too large. Unlike
     * {@link #countUpTo} a timeout is not a lower bound: it is Spring's {@link QueryTimeoutException}, and the
     * export is refused.
     */
    public long countForExport(AuditEventQuery query, int upTo) {
        Statement count = countStatement(query, upTo);
        Long counted = translatingTimeouts(() -> jdbc.queryForObject(count.sql(), count.params(), Long.class));
        return counted == null ? 0 : counted;
    }

    /**
     * Serialises the organization's exports until the caller's transaction ends, so two exports cannot both
     * pass the per-hour limit on the last slot. Sets the
     * transaction's {@code lock_timeout} to {@code certping.audit.export-lock-timeout-ms}.
     */
    public void lockExports(long organizationId) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("the export lock is held until the caller's transaction ends");
        }
        // Waits at most export-lock-timeout-ms for another export of the organization, then fails with
        // lock_not_available (isLockNotAvailable): the caller is told to retry, never left holding a connection.
        jdbc.getJdbcTemplate().execute("SET LOCAL lock_timeout = '" + exportLockTimeoutMillis + "ms'");
        translatingTimeouts(() -> jdbc.query(
                "SELECT pg_advisory_xact_lock(hashtextextended('audit-export', :organizationId))",
                new MapSqlParameterSource("organizationId", organizationId), rs -> null));
    }

    /**
     * The organization's exports (of the audit log or the access log, refused or not) since {@code since}, and
     * the time of the oldest: the limit frees a slot an hour after it.
     */
    public RecentExports exportsSince(long organizationId, Instant since) {
        MapSqlParameterSource params = new MapSqlParameterSource("organizationId", organizationId)
                .addValue("since", utc(since)).addValue("events", EXPORT_EVENTS);
        return translatingTimeouts(() -> jdbc.queryForObject("SELECT count(*) AS exports, min(occurred_at) AS oldest "
                        + "FROM audit_events WHERE visibility = 'CUSTOMER' AND organization_id = :organizationId "
                        + "AND occurred_at >= :since AND event IN (:events)", params,
                (rs, n) -> {
                    OffsetDateTime oldest = rs.getObject("oldest", OffsetDateTime.class);
                    return new RecentExports(rs.getLong("exports"), oldest == null ? null : oldest.toInstant());
                }));
    }

    /** An organization's recent exports: how many, and when the oldest of them was made ({@code null}: none). */
    public record RecentExports(long count, Instant oldest) {
    }

    /**
     * Users by id, deleted ones included (marked {@link LiveUser#deleted}): email, display name, organization and
     * whether they are a super admin. Name only {@link LiveUser#live} ones.
     */
    public Map<Integer, LiveUser> users(Collection<Integer> ids) {
        Map<Integer, LiveUser> users = new HashMap<>();
        if (ids.isEmpty()) {
            return users;
        }
        translatingTimeouts(() -> {
            jdbc.query("SELECT u.id, u.email, u.display_name, u.organization_id, u.is_deleted, "
                            + "EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                            + "WHERE ur.user_id = u.id AND r.name = 'SUPER_ADMIN' AND r.organization_id IS NULL "
                            + "AND ur.is_deleted = false AND r.is_deleted = false) "
                            + "AS super_admin FROM users u WHERE u.id IN (:ids)",
                    new MapSqlParameterSource("ids", ids), rs -> {
                        users.put(rs.getInt("id"), new LiveUser(rs.getString("email"), rs.getString("display_name"),
                                rs.getObject("organization_id", Long.class), rs.getBoolean("super_admin"),
                                rs.getBoolean("is_deleted")));
                    });
            return null;
        });
        return users;
    }

    /** Live organization names by id, not deleted. */
    public Map<Long, String> organizationNames(Collection<Long> ids) {
        Map<Long, String> names = new HashMap<>();
        if (ids.isEmpty()) {
            return names;
        }
        translatingTimeouts(() -> {
            jdbc.query("SELECT id, name FROM organizations WHERE id IN (:ids) AND is_deleted = false",
                    new MapSqlParameterSource("ids", ids), rs -> {
                        names.put(rs.getLong("id"), rs.getString("name"));
                    });
            return null;
        });
        return names;
    }

    /**
     * A user as the read side knows them: the display name, else the email, for naming (a deleted user is never
     * named, see {@link #live}), and whether they hold the platform's SUPER_ADMIN role (a requester who does reads
     * as Platform administrator; a deleted one too).
     *
     * @param organizationId the user's organization; {@code null} for a platform (staff) account
     * @param superAdmin     the user holds the platform's SUPER_ADMIN role (the system role; a soft-deleted
     *                       assignment or role does not count)
     * @param deleted        the user is deleted: never named
     */
    public record LiveUser(String email, String displayName, Long organizationId, boolean superAdmin,
                           boolean deleted) {

        /** A live member who is not a super admin. */
        public LiveUser(String email, String displayName, Long organizationId) {
            this(email, displayName, organizationId, false, false);
        }

        /** The user, unless deleted: who the read side may name. */
        public static LiveUser live(Map<Integer, LiveUser> users, Integer id) {
            LiveUser user = id == null ? null : users.get(id);
            return user == null || user.deleted() ? null : user;
        }

        public String name() {
            return displayName != null && !displayName.isBlank() ? displayName : email;
        }
    }

    /**
     * The WHERE clause of a query, scoped by its {@link AuditTrailView}. Every filter value is a bound
     * parameter; the visibility and the views' categories are literals, never parameters, so the partial
     * customer indexes stay usable under generic plans.
     *
     * <ul>
     *   <li>{@link AuditTrailView#ACTIVITY}: the organization's customer rows. Without a category the
     *       {@link AuditCategory#ACCESS} rows are left out: they are the Access view's, and the list shows them
     *       only for {@code category=ACCESS}.</li>
     *   <li>{@link AuditTrailView#ACCESS}: the organization's {@link AuditCategory#ACCESS} rows only.</li>
     *   <li>{@link AuditTrailView#PLATFORM}: rows of either visibility (or the one asked for), of one
     *       organization or all; served by the {@code (organization_id, occurred_at)} and {@code (occurred_at)}
     *       indexes, and by the customer ones when the visibility is {@code CUSTOMER}.</li>
     * </ul>
     *
     * Only a super admin's query may leave the organization out, and only a super admin's query may be a
     * platform one.
     */
    static String where(AuditEventQuery q, MapSqlParameterSource params) {
        if (!q.superAdmin() && (q.organizationId() == null || q.view() == AuditTrailView.PLATFORM)) {
            // Defence in depth: the controller resolves the caller's organization; a query without one
            // would read every organization's trail.
            throw new IllegalStateException("a customer audit query must name its organization");
        }
        List<String> conditions = new ArrayList<>();
        if (q.view() != AuditTrailView.PLATFORM) {
            conditions.add("visibility = 'CUSTOMER'");
        } else if (q.visibility() == AuditVisibility.CUSTOMER) {
            conditions.add("visibility = 'CUSTOMER'");
        } else if (q.visibility() == AuditVisibility.INTERNAL) {
            conditions.add("visibility = 'INTERNAL'");
        }
        if (q.organizationId() != null) {
            conditions.add("organization_id = :organizationId");
            params.addValue("organizationId", q.organizationId());
        }
        if (q.from() != null) {
            conditions.add("occurred_at >= :from");
            params.addValue("from", utc(q.from()));
        }
        if (q.to() != null) {
            conditions.add("occurred_at <= :to");
            params.addValue("to", utc(q.to()));
        }
        if (q.userId() != null) {
            conditions.add("actor_user_id = :userId");
            params.addValue("userId", q.userId());
        }
        if (q.actorType() != null) {
            conditions.add("actor_type = :actorType");
            params.addValue("actorType", q.actorType().name());
        }
        if (q.action() != null) {
            conditions.add("action = :action");
            params.addValue("action", q.action());
        }
        if (q.events() != null) {
            if (q.events().isEmpty()) {
                conditions.add("false");
            } else {
                conditions.add("event IN (:events)");
                params.addValue("events", q.events());
            }
        }
        switch (q.view()) {
            case ACCESS -> conditions.add("category = 'ACCESS'");
            case ACTIVITY -> {
                if (q.category() == null) {
                    // Sensitive reads belong to the Access view: the list shows them only when asked by category.
                    conditions.add("category <> 'ACCESS'");
                } else {
                    conditions.add("category = :category");
                    params.addValue("category", q.category().name());
                }
            }
            case PLATFORM -> {
                if (q.category() != null) {
                    conditions.add("category = :category");
                    params.addValue("category", q.category().name());
                }
            }
        }
        if (q.resourceType() != null) {
            conditions.add("resource_type = :resourceType");
            params.addValue("resourceType", q.resourceType());
        }
        if (q.resourceId() != null) {
            conditions.add("resource_id = :resourceId");
            params.addValue("resourceId", q.resourceId());
        }
        if (q.resourceRef() != null) {
            conditions.add("resource_ref = :resourceRef");
            params.addValue("resourceRef", q.resourceRef());
        }
        if (q.resourceName() != null) {
            conditions.add("lower(resource_name) = lower(:resourceName)");
            params.addValue("resourceName", q.resourceName(), Types.VARCHAR);
        }
        if (q.outcome() != null) {
            conditions.add("outcome = :outcome");
            params.addValue("outcome", q.outcome().name());
        }
        if (!q.hiddenFeatureKeys().isEmpty()) {
            conditions.add("(feature_key IS NULL OR feature_key NOT IN (:hiddenFeatureKeys))");
            params.addValue("hiddenFeatureKeys", q.hiddenFeatureKeys());
        }
        if (q.requestId() != null) {
            conditions.add("request_id = :requestId");
            params.addValue("requestId", q.requestId());
        }
        if (q.correlationId() != null) {
            conditions.add("correlation_id = :correlationId");
            params.addValue("correlationId", q.correlationId());
        }
        return conditions.isEmpty() ? "WHERE true" : "WHERE " + String.join(" AND ", conditions);
    }

    private static OffsetDateTime utc(Instant instant) {
        return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    /** A statement Postgres cancelled (57014) as Spring's {@link QueryTimeoutException}. */
    private static <T> T translatingTimeouts(Supplier<T> work) {
        try {
            return work.get();
        } catch (QueryTimeoutException timedOut) {
            throw timedOut;
        } catch (DataAccessException failed) {
            if (SqlStates.isQueryCanceled(failed)) {
                throw new QueryTimeoutException("audit_events query timed out", failed);
            }
            throw failed;
        }
    }


    /**
     * Runs {@code work} behind a savepoint on the transaction's connection when one is open, rolling back
     * to it when {@code work} fails, so the transaction stays usable for the queries that follow.
     */
    private <T> T behindSavepoint(Supplier<T> work) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            return work.get();
        }
        Connection connection = DataSourceUtils.getConnection(dataSource);
        try {
            Savepoint savepoint = savepoint(connection);
            T result;
            try {
                result = work.get();
            } catch (RuntimeException failed) {
                try {
                    connection.rollback(savepoint);
                } catch (SQLException rollbackFailed) {
                    failed.addSuppressed(rollbackFailed);
                }
                release(connection, savepoint, failed);
                throw failed;
            }
            release(connection, savepoint, null);
            return result;
        } finally {
            DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }

    private static Savepoint savepoint(Connection connection) {
        try {
            return connection.setSavepoint();
        } catch (SQLException e) {
            throw new IllegalStateException("could not set a savepoint for the audit count", e);
        }
    }

    private static void release(Connection connection, Savepoint savepoint, RuntimeException pending) {
        try {
            connection.releaseSavepoint(savepoint);
        } catch (SQLException releaseFailed) {
            if (pending != null) {
                pending.addSuppressed(releaseFailed);
            } else {
                throw new IllegalStateException("could not release the audit count savepoint", releaseFailed);
            }
        }
    }
}
