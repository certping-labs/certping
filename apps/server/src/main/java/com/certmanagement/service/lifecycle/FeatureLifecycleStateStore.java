// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.lifecycle.FeatureLifecycleState.Transition;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

/** Reads and writes {@code feature_lifecycle_state} rows. */
@Component
@RequiredArgsConstructor
class FeatureLifecycleStateStore {

    private static final String COLUMNS = "organization_id, feature_key, platform_paused, transition_seq, notified_seq,"
            + " pending_transition, CAST(pending_items AS text) AS pending_items, pending_occurred_at,"
            + " applied_transition_id, paused_claimed_seq";
    private static final TypeReference<List<AffectedItems>> ITEMS = new TypeReference<>() { };

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    /** The row, locked for the rest of the transaction (the caller also holds the advisory lock). */
    Optional<FeatureLifecycleState> findForUpdate(long organizationId, String featureKey) {
        return jdbc.query("SELECT " + COLUMNS + " FROM feature_lifecycle_state"
                        + " WHERE organization_id = :organizationId AND feature_key = :featureKey FOR UPDATE",
                key(organizationId, featureKey), rowMapper()).stream().findFirst();
    }

    void save(FeatureLifecycleState state) {
        jdbc.update("""
                INSERT INTO feature_lifecycle_state (organization_id, feature_key, platform_paused, transition_seq,
                       notified_seq, pending_transition, pending_items, pending_occurred_at,
                       applied_transition_id, paused_claimed_seq, updated_at)
                VALUES (:organizationId, :featureKey, :platformPaused, :transitionSeq, :notifiedSeq,
                        :pendingTransition, CAST(:pendingItems AS jsonb), :pendingOccurredAt,
                        :appliedTransitionId, :pausedClaimedSeq, NOW())
                ON CONFLICT (organization_id, feature_key) DO UPDATE SET
                       platform_paused = EXCLUDED.platform_paused, transition_seq = EXCLUDED.transition_seq,
                       notified_seq = EXCLUDED.notified_seq, pending_transition = EXCLUDED.pending_transition,
                       pending_items = EXCLUDED.pending_items, pending_occurred_at = EXCLUDED.pending_occurred_at,
                       applied_transition_id = GREATEST(feature_lifecycle_state.applied_transition_id,
                                                        EXCLUDED.applied_transition_id),
                       paused_claimed_seq = GREATEST(feature_lifecycle_state.paused_claimed_seq,
                                                     EXCLUDED.paused_claimed_seq),
                       updated_at = NOW()
                """, key(state.organizationId(), state.featureKey())
                .addValue("platformPaused", state.platformPaused())
                .addValue("transitionSeq", state.transitionSeq())
                .addValue("notifiedSeq", state.notifiedSeq())
                .addValue("appliedTransitionId", state.appliedTransitionId())
                .addValue("pausedClaimedSeq", state.pausedClaimedSeq())
                .addValue("pendingTransition",
                        state.pendingTransition() == null ? null : state.pendingTransition().name(), Types.VARCHAR)
                .addValue("pendingItems", state.pendingTransition() == null ? null : toJson(state.pendingItems()),
                        Types.VARCHAR)
                .addValue("pendingOccurredAt", state.pendingOccurredAt() == null ? null
                        : state.pendingOccurredAt().atOffset(ZoneOffset.UTC), Types.TIMESTAMP_WITH_TIMEZONE));
    }

    /** One page of organizations the platform has {@code featureKey} paused for, ascending after {@code after}. */
    List<Long> platformPausedOrganizations(String featureKey, long after, int limit) {
        return jdbc.queryForList("SELECT organization_id FROM feature_lifecycle_state"
                        + " WHERE feature_key = :featureKey AND platform_paused = TRUE AND organization_id > :after"
                        + " ORDER BY organization_id LIMIT :limit",
                new MapSqlParameterSource().addValue("featureKey", featureKey).addValue("after", after)
                        .addValue("limit", limit), Long.class);
    }

    /** Up to {@code limit} rows whose latest transition's email is still owed. */
    List<FeatureLifecycleState> findNotificationOwed(int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM feature_lifecycle_state"
                        + " WHERE notified_seq < transition_seq ORDER BY organization_id, feature_key LIMIT :limit",
                new MapSqlParameterSource("limit", limit), rowMapper());
    }

    /**
     * Records that transition {@code seq}'s email went out. Only moves forward; the owed email fields are
     * cleared only when no later transition has replaced them.
     */
    void markNotified(long organizationId, String featureKey, long seq) {
        jdbc.update("""
                UPDATE feature_lifecycle_state
                   SET notified_seq = GREATEST(notified_seq, :seq),
                       pending_transition = CASE WHEN transition_seq = :seq THEN NULL ELSE pending_transition END,
                       pending_items = CASE WHEN transition_seq = :seq THEN NULL ELSE pending_items END,
                       updated_at = NOW()
                 WHERE organization_id = :organizationId AND feature_key = :featureKey AND notified_seq < :seq
                """, key(organizationId, featureKey).addValue("seq", seq));
    }

    /**
     * Claims PAUSED transition {@code seq}'s email for publishing, in its own statement (autocommitted:
     * the notifier runs outside any transaction), before it is published. A resume that later ends
     * this pause sees the claim and owes a RESUMED email, even while the publish is in flight.
     *
     * @return false when the transition is no longer the current, owed PAUSED one (a resume came
     *         first and withdrew it): the email must not go out
     */
    boolean claimPausedNotice(long organizationId, String featureKey, long seq) {
        return jdbc.update("""
                UPDATE feature_lifecycle_state
                   SET paused_claimed_seq = GREATEST(paused_claimed_seq, :seq), updated_at = NOW()
                 WHERE organization_id = :organizationId AND feature_key = :featureKey
                   AND transition_seq = :seq AND pending_transition = 'PAUSED' AND platform_paused = TRUE
                """, key(organizationId, featureKey).addValue("seq", seq)) > 0;
    }

    private static MapSqlParameterSource key(long organizationId, String featureKey) {
        return new MapSqlParameterSource().addValue("organizationId", organizationId)
                .addValue("featureKey", featureKey);
    }

    private RowMapper<FeatureLifecycleState> rowMapper() {
        return (rows, rowNum) -> {
            String transition = rows.getString("pending_transition");
            Timestamp occurredAt = rows.getTimestamp("pending_occurred_at");
            return new FeatureLifecycleState(rows.getLong("organization_id"), rows.getString("feature_key"),
                    rows.getBoolean("platform_paused"), rows.getLong("transition_seq"), rows.getLong("notified_seq"),
                    transition == null ? null : Transition.valueOf(transition),
                    fromJson(rows.getString("pending_items")),
                    occurredAt == null ? null : occurredAt.toInstant(), rows.getLong("applied_transition_id"),
                    rows.getLong("paused_claimed_seq"));
        };
    }

    private String toJson(List<AffectedItems> items) {
        try {
            return objectMapper.writeValueAsString(items);
        } catch (JacksonException e) {
            throw new IllegalStateException("Lifecycle items could not be serialized", e);
        }
    }

    private List<AffectedItems> fromJson(String json) {
        if (json == null) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, ITEMS);
        } catch (JacksonException e) {
            throw new IllegalStateException("Lifecycle items could not be read", e);
        }
    }
}
