// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.core.JacksonException;

import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The only code that touches {@code audit_events}. Plain JDBC rather than JPA: the table is partitioned
 * and append-only, and its queries (partition pruning, keyset paging, the partial customer indexes)
 * are clearer written out. There is no entity, so Hibernate's schema validation never sees it.
 *
 * <p>Every row is sanitised here ({@link AuditSanitizer}). The actor's label (name, else email) is
 * snapshotted when left empty, from a five-minute cache filled by one query per batch, so a removed
 * member still reads as who acted until an erasure pseudonymises it. The organization's name is not
 * stored; the read side renders it live ({@link AuditDisplayNames#organization}).
 *
 * <p>Customer queries must spell {@code visibility = 'CUSTOMER'} as a literal, never a bound
 * parameter, so the partial indexes stay usable under a generic plan.
 */
@Repository
public class AuditEventStore {

    /** What a GDPR erasure replaces an actor's label with; {@code audit_events_refuse_change} allows only this. */
    public static final String ERASED_ACTOR_LABEL = "Former member";

    /** Partition DDL waits at most this long for its lock; the job tries again on its next run. */
    static final String PARTITION_LOCK_TIMEOUT = "SET LOCAL lock_timeout = '5s'";

    /** Each single-month drop waits at most this long for its lock; a busy month is left for the next run. */
    static final String DROP_LOCK_TIMEOUT = "SET LOCAL lock_timeout = '2s'";

    /** The advisory-lock key one retention run holds, so only one pod drops at a time. */
    static final String RETENTION_LOCK = "audit_events_retention";

    private static final String INSERT = """
            INSERT INTO audit_events (occurred_at, visibility, event, category, feature_key, organization_id,
                actor_type, actor_user_id, actor_label, actor_job, actor_staff, auth_method,
                action, resource_type, resource_id, resource_ref, resource_name, outcome, error_code, summary,
                details, ip_address, user_agent, request_id, correlation_id, trace_id)
            VALUES (:occurredAt, :visibility, :event, :category, :featureKey, :organizationId,
                :actorType, :actorUserId, :actorLabel, :actorJob, :actorStaff, :authMethod,
                :action, :resourceType, :resourceId, :resourceRef, :resourceName, :outcome, :errorCode, :summary,
                CAST(:details AS jsonb), :ipAddress, :userAgent, :requestId, :correlationId, :traceId)
            """;

    /** Erasures update at most this many actors per statement. */
    private static final int ERASURE_CHUNK = 1_000;

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate ownTransaction;
    private final TransactionTemplate joinedTransaction;
    private final Cache<Integer, String> actors = labelCache();

    public AuditEventStore(NamedParameterJdbcTemplate jdbc, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.ownTransaction = new TransactionTemplate(transactionManager);
        this.ownTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.joinedTransaction = new TransactionTemplate(transactionManager);
    }

    /** Writes one row on the current transaction's connection, or on its own when there is none. */
    public void insert(AuditEventRow row) {
        insertAll(List.of(row));
    }

    /**
     * Writes the rows in JDBC batches, on the current transaction's connection when there is one.
     *
     * @return the rows written
     */
    public int insertAll(List<AuditEventRow> rows) {
        if (rows.isEmpty()) {
            return 0;
        }
        List<SqlParameterSource> batch = new ArrayList<>(rows.size());
        for (AuditEventRow row : withActorLabels(rows)) {
            batch.add(parameters(AuditSanitizer.sanitize(row)));
        }
        if (batch.size() == 1) {
            return jdbc.update(INSERT, batch.get(0));
        }
        int written = 0;
        for (int count : jdbc.batchUpdate(INSERT, batch.toArray(SqlParameterSource[]::new))) {
            // SUCCESS_NO_INFO (-2): the driver wrote the row but did not say.
            written += count == java.sql.Statement.SUCCESS_NO_INFO ? 1 : Math.max(count, 0);
        }
        return written;
    }

    /**
     * Creates the partition for {@code month} unless it exists, in a transaction of its own; returns its
     * name when this call created it. A month older than the retention cutoff in force
     * ({@link #retentionCutoffInForce()}) is refused, whoever asks: the retention job dropped it, or will.
     *
     * @throws IllegalArgumentException when {@code month} is older than the retention cutoff in force
     */
    public Optional<String> createPartition(YearMonth month) {
        OffsetDateTime firstDay = month.atDay(1).atStartOfDay().atOffset(ZoneOffset.UTC);
        return ownTransaction.execute(status -> {
            Optional<Instant> floor = retentionCutoffInForce();
            if (floor.isPresent() && firstDay.toInstant().isBefore(floor.get())) {
                // A month the retention period has expired: recreating it would bring back what was dropped.
                throw new IllegalArgumentException("audit month " + month + " is older than the retention cutoff "
                        + floor.get() + "; its partition is not created");
            }
            jdbc.getJdbcTemplate().execute(PARTITION_LOCK_TIMEOUT);
            return Optional.ofNullable(jdbc.queryForObject("SELECT audit_events_create_partition(:month)",
                    new MapSqlParameterSource("month", firstDay), String.class));
        });
    }

    /**
     * Drops the monthly partitions that ended at or before {@code cutoff}, in a transaction of its own;
     * the function refuses a cutoff later than six months ago. Returns the partitions dropped.
     */
    public List<String> dropPartitionsBefore(Instant cutoff) {
        return ownTransaction.execute(status -> {
            jdbc.getJdbcTemplate().execute(PARTITION_LOCK_TIMEOUT);
            return jdbc.queryForList("SELECT audit_events_drop_partitions_before(:cutoff)",
                    new MapSqlParameterSource("cutoff", OffsetDateTime.ofInstant(cutoff, ZoneOffset.UTC)), String.class);
        });
    }

    /**
     * Drops {@code month}'s partition in the caller's transaction, waiting at most two seconds for its lock;
     * returns its name, or empty when it was not attached. {@code audit_events_drop_partition} refuses a month
     * that ended later than six months ago and never touches the default partition. The caller commits right
     * after, so the brief ACCESS EXCLUSIVE lock on {@code audit_events} is held for one month only.
     *
     * @throws IllegalStateException when no transaction is active
     */
    public Optional<String> dropPartition(YearMonth month) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("a partition is dropped in the caller's transaction; none is active");
        }
        jdbc.getJdbcTemplate().execute(DROP_LOCK_TIMEOUT);
        return Optional.ofNullable(jdbc.queryForObject("SELECT audit_events_drop_partition(:month)",
                new MapSqlParameterSource("month", month.atDay(1)), String.class));
    }

    /**
     * The planner's row estimate ({@code pg_class.reltuples}, no scan) of each monthly partition that ended at
     * or before {@code cutoff}: what {@link #dropPartitionsBefore} would drop. A partition never analysed
     * reports {@code -1}.
     */
    public Map<String, Long> estimatedRowsOfPartitionsBefore(Instant cutoff) {
        Map<String, Long> estimates = new LinkedHashMap<>();
        jdbc.query("SELECT c.relname, c.reltuples::bigint AS estimate FROM pg_inherits i "
                        + "JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'audit_events'::regclass "
                        + "AND c.relname ~ '^audit_events_[0-9]{4}_[0-9]{2}$' "
                        + "AND (to_date(substr(c.relname, 14), 'YYYY_MM') + interval '1 month')::timestamp "
                        + "AT TIME ZONE 'UTC' <= :cutoff ORDER BY c.relname",
                new MapSqlParameterSource("cutoff", OffsetDateTime.ofInstant(cutoff, ZoneOffset.UTC)),
                rs -> {
                    estimates.put(rs.getString("relname"), rs.getLong("estimate"));
                });
        return estimates;
    }

    /** The month of the oldest monthly partition still attached, or empty when there is none. */
    public Optional<YearMonth> oldestPartitionMonth() {
        String oldest = jdbc.getJdbcTemplate().queryForObject("SELECT min(substr(c.relname, 14)) FROM pg_inherits i "
                + "JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'audit_events'::regclass "
                + "AND c.relname ~ '^audit_events_[0-9]{4}_[0-9]{2}$'", String.class);
        return Optional.ofNullable(oldest).map(suffix -> YearMonth.parse(suffix.replace('_', '-')));
    }

    /**
     * The retention cutoff in force (the first day of (current UTC month − {@code audit_retention_months}), by the
     * database's clock), or empty while the setting is unconfirmed or not a whole number from
     * {@value AuditRetentionService#MIN_MONTHS} to {@value AuditRetentionService#MAX_MONTHS}: nothing older is
     * kept, so nothing older may be created or copied again. Joins the caller's transaction when there is one.
     */
    public Optional<Instant> retentionCutoffInForce() {
        List<OffsetDateTime> cutoff = jdbc.query("""
                SELECT (date_trunc('month', now() AT TIME ZONE 'UTC') - make_interval(months => s.months))
                       AT TIME ZONE 'UTC' AS cutoff
                FROM (SELECT CASE WHEN m.value ~ '^\\s*[0-9]{1,3}\\s*$' THEN trim(m.value)::int END AS months
                      FROM global_settings m
                      WHERE m.key = :monthsKey
                        AND EXISTS (SELECT 1 FROM global_settings c WHERE c.key = :confirmedKey)) s
                WHERE s.months BETWEEN :min AND :max
                """, new MapSqlParameterSource("monthsKey", AuditRetentionService.SETTING_KEY)
                        .addValue("confirmedKey", AuditRetentionService.CONFIRMED_AT_KEY)
                        .addValue("min", AuditRetentionService.MIN_MONTHS)
                        .addValue("max", AuditRetentionService.MAX_MONTHS),
                (rs, i) -> rs.getObject("cutoff", OffsetDateTime.class));
        return cutoff.stream().findFirst().map(OffsetDateTime::toInstant);
    }

    /**
     * Takes the retention job's advisory lock for the current transaction, without waiting: {@code false} when
     * another pod's run holds it. The lock goes with the transaction, so a pod that dies mid-run never leaves it
     * held. Must be called inside the transaction that does the work: on its own it would be released at once.
     *
     * @throws IllegalStateException when no transaction is active
     */
    public boolean tryRetentionLock() {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("the retention lock is held by a transaction; none is active");
        }
        Boolean locked = jdbc.getJdbcTemplate().queryForObject(
                "SELECT pg_try_advisory_xact_lock(hashtextextended(?, 0))", Boolean.class, RETENTION_LOCK);
        return Boolean.TRUE.equals(locked);
    }

    /**
     * Whether {@code organizationId}'s trail holds a row of {@code event} about {@code resourceRef} written since
     * {@code since}: one probe of the target index, pruned to the partitions since then.
     */
    public boolean existsSince(long organizationId, String event, String resourceType, String resourceRef,
                               Instant since) {
        Boolean exists = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM audit_events WHERE organization_id = :org"
                        + " AND resource_type = :type AND resource_ref = :ref AND event = :event"
                        + " AND occurred_at >= :since)",
                new MapSqlParameterSource("org", organizationId).addValue("type", resourceType)
                        .addValue("ref", resourceRef).addValue("event", event)
                        .addValue("since", OffsetDateTime.ofInstant(since, ZoneOffset.UTC)), Boolean.class);
        return Boolean.TRUE.equals(exists);
    }

    /** How many rows sit in the default partition, counted up to {@code upTo}. */
    public int defaultPartitionRows(int upTo) {
        Integer rows = jdbc.queryForObject(
                "SELECT count(*) FROM (SELECT 1 FROM audit_events_default LIMIT :upTo) AS sample",
                new MapSqlParameterSource("upTo", upTo), Integer.class);
        return rows == null ? 0 : rows;
    }

    /**
     * GDPR erasure: replaces the label of every row {@code userId} acted in with
     * {@link #ERASED_ACTOR_LABEL}, the one change the append-only trigger allows, and only while
     * {@code certping.audit_erasure} is on, which this sets and clears around the update. Joins the
     * caller's transaction when there is one. Rows about the member need no change: their name is never
     * stored ({@link AuditEventType#rendersTargetWhenRead()}).
     *
     * @return the rows changed
     */
    public int pseudonymiseActor(int userId) {
        return pseudonymiseActors(List.of(userId));
    }

    /**
     * {@link #pseudonymiseActor} for several users at once (an organization's purged members), in
     * statements of at most a thousand ids, joining the caller's transaction when there is one.
     *
     * @return the rows changed
     */
    public int pseudonymiseActors(Collection<Integer> userIds) {
        if (userIds.isEmpty()) {
            return 0;
        }
        List<Integer> ids = List.copyOf(new LinkedHashSet<>(userIds));
        Integer changed = joinedTransaction.execute(status -> {
            jdbc.getJdbcTemplate().queryForObject("SELECT set_config('certping.audit_erasure', 'on', true)", String.class);
            int rows = 0;
            for (int from = 0; from < ids.size(); from += ERASURE_CHUNK) {
                rows += jdbc.update("UPDATE audit_events SET actor_label = :label "
                                + "WHERE actor_user_id IN (:userIds) AND actor_label IS DISTINCT FROM :label",
                        new MapSqlParameterSource("label", ERASED_ACTOR_LABEL)
                                .addValue("userIds", ids.subList(from, Math.min(ids.size(), from + ERASURE_CHUNK))));
            }
            jdbc.getJdbcTemplate().queryForObject("SELECT set_config('certping.audit_erasure', 'off', true)", String.class);
            actors.invalidateAll(ids);
            return rows;
        });
        return changed == null ? 0 : changed;
    }

    /**
     * Fills empty actor labels from the user (display name, else email), with one query for the cache misses of
     * the whole batch. Ids the database does not know map to an empty label, so a miss is cached too.
     */
    private List<AuditEventRow> withActorLabels(List<AuditEventRow> rows) {
        Set<Integer> users = new HashSet<>();
        for (AuditEventRow row : rows) {
            if (row.actorUserId() != null && row.actorLabel() == null) {
                users.add(row.actorUserId());
            }
        }
        if (users.isEmpty()) {
            return rows;
        }
        Map<Integer, String> labels = actors.getAll(users, this::loadLabels);
        List<AuditEventRow> named = new ArrayList<>(rows.size());
        for (AuditEventRow row : rows) {
            named.add(row.actorUserId() == null || row.actorLabel() != null ? row
                    : row.toBuilder().actorLabel(blankToNull(labels.get(row.actorUserId()))).build());
        }
        return named;
    }

    private Map<Integer, String> loadLabels(Set<? extends Integer> ids) {
        Map<Integer, String> labels = new LinkedHashMap<>();
        ids.forEach(id -> labels.put(id, ""));
        jdbc.query("SELECT id, display_name, email FROM users WHERE id IN (:ids)",
                new MapSqlParameterSource("ids", ids), rs -> {
                    String name = rs.getString("display_name");
                    labels.put(rs.getInt("id"), name != null && !name.isBlank() ? name : rs.getString("email"));
                });
        return labels;
    }

    private static MapSqlParameterSource parameters(AuditEventRow row) {
        return new MapSqlParameterSource()
                .addValue("occurredAt", OffsetDateTime.ofInstant(row.occurredAt(), ZoneOffset.UTC))
                .addValue("visibility", row.visibility().name())
                .addValue("event", row.event(), Types.VARCHAR)
                .addValue("category", row.category(), Types.VARCHAR)
                .addValue("featureKey", row.featureKey(), Types.VARCHAR)
                .addValue("organizationId", row.organizationId(), Types.BIGINT)
                .addValue("actorType", row.actorType().name())
                .addValue("actorUserId", row.actorUserId(), Types.INTEGER)
                .addValue("actorLabel", row.actorLabel(), Types.VARCHAR)
                .addValue("actorJob", row.actorJob(), Types.VARCHAR)
                .addValue("actorStaff", row.actorStaff())
                .addValue("authMethod", row.authMethod(), Types.VARCHAR)
                .addValue("action", row.action())
                .addValue("resourceType", row.resourceType())
                .addValue("resourceId", row.resourceId(), Types.BIGINT)
                .addValue("resourceRef", row.resourceRef(), Types.VARCHAR)
                .addValue("resourceName", row.resourceName(), Types.VARCHAR)
                .addValue("outcome", row.outcome().name())
                .addValue("errorCode", row.errorCode(), Types.VARCHAR)
                .addValue("summary", row.summary())
                .addValue("details", detailsJson(row.details()), Types.VARCHAR)
                .addValue("ipAddress", row.ipAddress(), Types.VARCHAR)
                .addValue("userAgent", row.userAgent(), Types.VARCHAR)
                .addValue("requestId", row.requestId(), Types.VARCHAR)
                .addValue("correlationId", row.correlationId(), Types.VARCHAR)
                .addValue("traceId", row.traceId(), Types.VARCHAR);
    }

    /** {@code {"kind":"event","changes":[...],"attributes":{...}}}, or null when there is nothing. */
    static String detailsJson(AuditDetails details) {
        if (details == null || details.isEmpty()) {
            return null;
        }
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("kind", "event");
        if (!details.changes().isEmpty()) {
            List<Map<String, String>> changes = new ArrayList<>(details.changes().size());
            for (AuditChange change : details.changes()) {
                Map<String, String> entry = new LinkedHashMap<>();
                entry.put("field", change.field());
                entry.put("before", change.before());
                entry.put("after", change.after());
                changes.add(entry);
            }
            json.put("changes", changes);
        }
        if (!details.attributes().isEmpty()) {
            json.put("attributes", details.attributes());
        }
        try {
            return JSON.writeValueAsString(json);
        } catch (JacksonException e) {
            throw new IllegalStateException("audit details could not be serialised", e);
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static Cache<Integer, String> labelCache() {
        return Caffeine.newBuilder().maximumSize(10_000).expireAfterWrite(Duration.ofMinutes(5)).build();
    }
}
