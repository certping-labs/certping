// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import com.certmanagement.repository.lifecycle.RecordImpact;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Set-based reads and the bulk cancel of running discovery scans (DISPATCHED or RECEIVING). A
 * cancelled scan ends CANCELLED like {@code DiscoveryScanService.markCancelled}; results that still
 * arrive for it are dropped by the existing CANCELLED check.
 */
@Repository
@RequiredArgsConstructor
public class DiscoveryLifecycleRepository {

    private static final String RUNNING = "status IN ('DISPATCHED', 'RECEIVING')";

    private final NamedParameterJdbcTemplate jdbc;

    public long countRunning(long organizationId) {
        Long count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM discovery_scan WHERE organization_id = :organizationId AND " + RUNNING,
                new MapSqlParameterSource("organizationId", organizationId), Long.class);
        return count == null ? 0 : count;
    }

    /** Running scans per organization, for a page of organizations (absent: none). */
    public Map<Long, Long> countRunningByOrganization(Collection<Long> organizationIds) {
        if (organizationIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, Long> counts = new HashMap<>();
        jdbc.query("SELECT organization_id, COUNT(*) AS running FROM discovery_scan"
                        + " WHERE organization_id IN (:organizationIds) AND " + RUNNING + " GROUP BY organization_id",
                new MapSqlParameterSource("organizationIds", organizationIds),
                rows -> { counts.put(rows.getLong("organization_id"), rows.getLong("running")); });
        return counts;
    }

    public RecordImpact impact(ImpactScope scope) {
        return jdbc.queryForObject("SELECT COUNT(*) AS records, COUNT(DISTINCT organization_id) AS organizations"
                        + " FROM discovery_scan WHERE " + RUNNING + scope.filter("organization_id"),
                scope.bind(new MapSqlParameterSource()),
                (rows, rowNum) -> new RecordImpact(rows.getLong("records"), rows.getLong("organizations")));
    }

    /** The organizations with running scans within {@code scope}, for a cross-kind distinct count. */
    public AffectedOrganizations runningScanOrganizations(ImpactScope scope) {
        return new AffectedOrganizations("SELECT organization_id FROM discovery_scan WHERE " + RUNNING
                + scope.filter("organization_id"), scope.bind(new MapSqlParameterSource()));
    }

    public List<Long> organizationsWithRunningScans(long afterOrganizationId, int limit) {
        return jdbc.queryForList("SELECT DISTINCT organization_id FROM discovery_scan WHERE " + RUNNING
                        + " AND organization_id > :after ORDER BY organization_id LIMIT :limit",
                new MapSqlParameterSource().addValue("after", afterOrganizationId).addValue("limit", limit),
                Long.class);
    }

    /**
     * Cancels the organization's running scans and moves the configurations that ran them to
     * CANCELLED with {@code statusMessage}, in one statement (Postgres runs every data-modifying
     * CTE to completion whether or not the outer query reads it).
     *
     * @return scans cancelled
     */
    public int cancelRunning(long organizationId, String statusMessage) {
        Integer cancelled = jdbc.queryForObject("""
                        WITH cancelled AS (
                            UPDATE discovery_scan
                               SET status = 'CANCELLED', completed_at = NOW(), finalized_at = NOW(), updated_at = NOW()
                             WHERE organization_id = :organizationId AND status IN ('DISPATCHED', 'RECEIVING')
                         RETURNING request_id
                        ), configs AS (
                            UPDATE discovery_config
                               SET status = 'CANCELLED', status_message = :statusMessage, updated_at = NOW()
                             WHERE organization_id = :organizationId
                               AND status IN ('STARTED', 'IN_PROGRESS')
                               AND last_request_id IN (SELECT request_id FROM cancelled)
                         RETURNING id
                        )
                        SELECT COUNT(*) FROM cancelled
                        """,
                new MapSqlParameterSource().addValue("organizationId", organizationId)
                        .addValue("statusMessage", statusMessage),
                Integer.class);
        return cancelled == null ? 0 : cancelled;
    }
}
