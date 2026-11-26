// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.lifecycle.ForcedTransition.Scope;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/** Reads and writes {@code feature_lifecycle_transition} rows. */
@Component
@RequiredArgsConstructor
class ForcedTransitionStore {

    private static final String COLUMNS = "id, feature_key, scope, org_type, organization_id, before_enabled,"
            + " before_admin_locked, actor_user_id, cursor_phase, cursor_organization_id";
    private static final String PENDING = "'PENDING'";
    private static final String WRITE_LOCK_NAMESPACE = "certping:forced-transition:";

    private final NamedParameterJdbcTemplate jdbc;

    /**
     * Waits for and takes the feature's forced-transition write lock for the rest of the caller's
     * transaction. Ids come from a sequence at insert time, so without it two concurrent writes of one
     * feature could commit out of id order and a walker that already passed the higher id would never
     * see the lower one. Only flag writers take it; the reconciler never does.
     */
    void lockFeatureForWrite(String featureKey) {
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(:key)::text",
                new MapSqlParameterSource("key", writeLockKey(featureKey)), String.class);
    }

    /** The key of {@link #lockFeatureForWrite}, distinct from every {@link FeatureLifecycleLock} key. */
    static long writeLockKey(String featureKey) {
        return AdvisoryLockKeys.keyOf(WRITE_LOCK_NAMESPACE + featureKey);
    }

    /**
     * Records a forced change in the caller's transaction and supersedes the older pending changes of
     * the same scope: only the newest change of one layer is ever applied.
     *
     * @return the new row's id, which orders it after every earlier change
     */
    long insert(String featureKey, Scope scope, String orgType, Long organizationId, Boolean beforeEnabled,
                Boolean beforeAdminLocked, Boolean afterEnabled, Boolean afterAdminLocked, Integer actorUserId) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("featureKey", featureKey).addValue("scope", scope.name())
                .addValue("orgType", orgType, Types.VARCHAR).addValue("organizationId", organizationId, Types.BIGINT)
                .addValue("beforeEnabled", beforeEnabled, Types.BOOLEAN)
                .addValue("beforeAdminLocked", beforeAdminLocked, Types.BOOLEAN)
                .addValue("afterEnabled", afterEnabled, Types.BOOLEAN)
                .addValue("afterAdminLocked", afterAdminLocked, Types.BOOLEAN)
                .addValue("actorUserId", actorUserId, Types.INTEGER);
        jdbc.update("UPDATE feature_lifecycle_transition SET status = 'SUPERSEDED', updated_at = NOW()"
                + " WHERE feature_key = :featureKey AND scope = :scope AND status = " + PENDING
                + " AND org_type IS NOT DISTINCT FROM CAST(:orgType AS varchar)"
                + " AND organization_id IS NOT DISTINCT FROM CAST(:organizationId AS bigint)", params);
        Long id = jdbc.queryForObject("""
                INSERT INTO feature_lifecycle_transition (feature_key, scope, org_type, organization_id,
                       before_enabled, before_admin_locked, after_enabled, after_admin_locked, actor_user_id)
                VALUES (:featureKey, :scope, :orgType, :organizationId, :beforeEnabled, :beforeAdminLocked,
                        :afterEnabled, :afterAdminLocked, :actorUserId)
                RETURNING id
                """, params, Long.class);
        return id == null ? 0 : id;
    }

    /** The row if it is still pending (not yet complete, not superseded). */
    Optional<ForcedTransition> findPending(long id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM feature_lifecycle_transition"
                        + " WHERE id = :id AND status = " + PENDING,
                new MapSqlParameterSource("id", id), rowMapper()).stream().findFirst();
    }

    /**
     * The pending changes newer than {@code afterId} that can affect the organization, oldest first.
     * Read BEFORE the flag rows: a change visible here has committed its flag write too, so the flag
     * rows read afterwards never miss it (READ COMMITTED), and nothing is consumed unseen.
     */
    List<ForcedTransition> pendingCovering(Collection<String> featureKeys, long organizationId, long afterId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM feature_lifecycle_transition"
                        + " WHERE feature_key IN (:featureKeys) AND status = " + PENDING + " AND id > :afterId"
                        + " AND (scope = 'GLOBAL'"
                        + " OR (scope = 'ORGANIZATION' AND organization_id = :organizationId)"
                        + " OR (scope = 'ORG_TYPE' AND org_type ="
                        + " (SELECT o.org_type FROM organizations o WHERE o.id = :organizationId)))"
                        + " ORDER BY id",
                new MapSqlParameterSource().addValue("featureKeys", featureKeys).addValue("afterId", afterId)
                        .addValue("organizationId", organizationId), rowMapper());
    }

    /**
     * The pending changes of {@code featureKeys} that can cover any of {@code organizationIds} (every
     * GLOBAL and ORG_TYPE row, and the ORGANIZATION rows of those organizations); a few rows at most.
     */
    List<ForcedTransition> pendingFor(Collection<String> featureKeys, Collection<Long> organizationIds) {
        if (organizationIds.isEmpty()) {
            return List.of();
        }
        return jdbc.query("SELECT " + COLUMNS + " FROM feature_lifecycle_transition"
                        + " WHERE feature_key IN (:featureKeys) AND status = " + PENDING
                        + " AND (scope <> 'ORGANIZATION' OR organization_id IN (:organizationIds)) ORDER BY id",
                new MapSqlParameterSource().addValue("featureKeys", featureKeys)
                        .addValue("organizationIds", organizationIds), rowMapper());
    }

    /**
     * Pending rows nobody has advanced since {@code idleSince}: their after-commit run was lost (pod
     * stopped, executor full) or is stuck, so the backstop takes them over. Oldest first.
     */
    List<ForcedTransition> findIdle(Instant idleSince, int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM feature_lifecycle_transition"
                        + " WHERE status = " + PENDING + " AND updated_at < :idleSince ORDER BY id LIMIT :limit",
                new MapSqlParameterSource().addValue("idleSince", Timestamp.from(idleSince))
                        .addValue("limit", limit), rowMapper());
    }

    /**
     * Saves where an organization walk stands (also the row's heartbeat).
     *
     * @return false when the row is no longer pending (completed or superseded): the walk stops
     */
    boolean saveCursor(long id, SweepCursor.Pass phase, long organizationId) {
        return jdbc.update("UPDATE feature_lifecycle_transition SET cursor_phase = :phase,"
                        + " cursor_organization_id = :organizationId, updated_at = NOW()"
                        + " WHERE id = :id AND status = " + PENDING,
                new MapSqlParameterSource().addValue("id", id).addValue("phase", phase.name())
                        .addValue("organizationId", organizationId)) > 0;
    }

    /** Marks the row applied everywhere it covers; a superseded row stays superseded. */
    void markComplete(long id) {
        jdbc.update("UPDATE feature_lifecycle_transition SET status = 'COMPLETE', updated_at = NOW()"
                + " WHERE id = :id AND status = " + PENDING, new MapSqlParameterSource("id", id));
    }

    private static RowMapper<ForcedTransition> rowMapper() {
        return (rows, rowNum) -> new ForcedTransition(rows.getLong("id"), rows.getString("feature_key"),
                Scope.valueOf(rows.getString("scope")), rows.getString("org_type"),
                rows.getObject("organization_id", Long.class), rows.getObject("before_enabled", Boolean.class),
                rows.getObject("before_admin_locked", Boolean.class), rows.getObject("actor_user_id", Integer.class),
                SweepCursor.Pass.valueOf(rows.getString("cursor_phase")), rows.getLong("cursor_organization_id"));
    }
}
