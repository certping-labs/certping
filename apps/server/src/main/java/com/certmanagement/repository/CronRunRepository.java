// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CronRun;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;

@Repository
public interface CronRunRepository extends JpaRepository<CronRun, String> {

    @Modifying
    @Transactional
    @NativeQuery("""
        INSERT INTO cron_runs (cron_name, active_pod_count, last_activity_at)
        VALUES (:name, 1, NOW())
        ON CONFLICT (cron_name) DO UPDATE SET
            active_pod_count = cron_runs.active_pod_count + 1,
            last_activity_at = NOW()
        """)
    void increment(@Param("name") String cronName);

    /** Sets last_completed_at only on the 1 → 0 transition (last pod out records completion). */
    @Modifying
    @Transactional
    @NativeQuery("""
        UPDATE cron_runs SET
            active_pod_count  = GREATEST(0, active_pod_count - 1),
            last_activity_at  = NOW(),
            last_completed_at = CASE WHEN active_pod_count = 1 THEN NOW() ELSE last_completed_at END
        WHERE cron_name = :name
        """)
    void decrement(@Param("name") String cronName);

    /** Bumps last_activity_at without touching the counter — proves a pod is still draining. */
    @Modifying
    @Transactional
    @NativeQuery("UPDATE cron_runs SET last_activity_at = NOW() WHERE cron_name = :name")
    void heartbeat(@Param("name") String cronName);

    /** Race-safe reset — zero the counter only if the row is still stale at UPDATE time. */
    @Modifying
    @Transactional
    @NativeQuery("""
        UPDATE cron_runs
           SET active_pod_count = 0,
               last_activity_at = NOW()
         WHERE cron_name = :name
           AND last_activity_at < :staleCutoff
        """)
    int resetIfStale(@Param("name") String cronName,
                     @Param("staleCutoff") OffsetDateTime staleCutoff);

    /**
     * Records that a drain stopped on its budget with work left, so the supervisor continues it.
     * Upserts because the run's own increment may have failed to create the row.
     */
    @Modifying
    @Transactional
    @NativeQuery("""
        INSERT INTO cron_runs (cron_name, active_pod_count, last_activity_at, continuation_due_at)
        VALUES (:name, 0, NOW(), NOW())
        ON CONFLICT (cron_name) DO UPDATE SET continuation_due_at = NOW()
        """)
    void markContinuationDue(@Param("name") String cronName);

    /** Clears the continuation marker once a run has drained the backlog. */
    @Modifying
    @Transactional
    @NativeQuery("""
        UPDATE cron_runs SET continuation_due_at = NULL
         WHERE cron_name = :name AND continuation_due_at IS NOT NULL
        """)
    void clearContinuation(@Param("name") String cronName);

    /**
     * Drains with a continuation due that no pod is running: no active pod, or only a counter
     * leaked by a crashed pod (no activity since {@code staleCutoff}; a running drain heartbeats).
     * A running drain writes or clears the marker itself when it stops, so it is not joined here.
     * Unbounded on purpose: cron_runs has one row per drain job.
     */
    @NativeQuery("""
        SELECT cron_name FROM cron_runs
         WHERE continuation_due_at <= NOW()
           AND (active_pod_count = 0 OR last_activity_at < :staleCutoff)
         ORDER BY cron_name
        """)
    List<String> findIdleWithContinuationDue(@Param("staleCutoff") OffsetDateTime staleCutoff);
}
