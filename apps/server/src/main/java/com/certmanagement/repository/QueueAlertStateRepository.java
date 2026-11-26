// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.QueueAlertStateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Optional;

/**
 * State + cross-replica lock for {@link com.certmanagement.service.scheduler.QueueDepthAlertService}.
 *
 * <p>The server scales to multiple replicas with no leader election, so the alert state machine
 * is driven entirely through atomic conditional UPDATEs here. On a poll tick every replica may
 * observe the same breach; only the one whose {@link #claimFire} / {@link #claimRecover} affects
 * <b>1 row</b> is allowed to send the email. Under READ COMMITTED the losing replicas' WHERE
 * clauses re-evaluate against the winner's committed row and match 0 rows.
 */
@Repository
public interface QueueAlertStateRepository extends JpaRepository<QueueAlertStateEntity, Long> {

    Optional<QueueAlertStateEntity> findByEntityNameAndMetric(String entityName, String metric);

    /** Lazily create the OK baseline row for an (entity, metric); no-op if it already exists. */
    @Transactional
    @Modifying
    @NativeQuery("""
        INSERT INTO queue_alert_state
            (entity_name, metric, alert_state, last_value, consecutive_breaches, created_at, updated_at)
        VALUES (:entityName, :metric, 'OK', 0, 0, :now, :now)
        ON CONFLICT (entity_name, metric) DO NOTHING
        """)
    int ensureRow(@Param("entityName") String entityName,
                  @Param("metric") String metric,
                  @Param("now") OffsetDateTime now);

    /**
     * Atomically claim the right to FIRE an alert for this (entity, metric). Matches when the row
     * is not already ALERTING, or when it is but the cooldown has elapsed ({@code last_alerted_at
     * <= reAlertCutoff}). Returns 1 for the single winning replica, 0 for everyone else.
     */
    @Transactional
    @Modifying
    @NativeQuery("""
        UPDATE queue_alert_state
           SET alert_state = 'ALERTING',
               last_value = :value,
               consecutive_breaches = consecutive_breaches + 1,
               last_alerted_at = :now,
               recovered_at = NULL,
               updated_at = :now
         WHERE entity_name = :entityName
           AND metric = :metric
           AND (alert_state <> 'ALERTING'
                OR last_alerted_at IS NULL
                OR last_alerted_at <= :reAlertCutoff)
        """)
    int claimFire(@Param("entityName") String entityName,
                  @Param("metric") String metric,
                  @Param("value") long value,
                  @Param("now") OffsetDateTime now,
                  @Param("reAlertCutoff") OffsetDateTime reAlertCutoff);

    /**
     * Atomically claim the right to send the RECOVERED email: flips ALERTING → OK. Returns 1 for
     * the single winning replica, 0 for everyone else (including when already OK).
     */
    @Transactional
    @Modifying
    @NativeQuery("""
        UPDATE queue_alert_state
           SET alert_state = 'OK',
               last_value = :value,
               consecutive_breaches = 0,
               recovered_at = :now,
               updated_at = :now
         WHERE entity_name = :entityName
           AND metric = :metric
           AND alert_state = 'ALERTING'
        """)
    int claimRecover(@Param("entityName") String entityName,
                     @Param("metric") String metric,
                     @Param("value") long value,
                     @Param("now") OffsetDateTime now);
}
