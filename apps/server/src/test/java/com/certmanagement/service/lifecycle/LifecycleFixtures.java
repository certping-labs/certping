// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

/**
 * Rows the feature lifecycle Postgres tests build on: organizations with running discovery scans
 * (the records the {@code DISCOVERY} lifecycle pauses, by cancelling them) and flag overrides at
 * every layer.
 */
final class LifecycleFixtures {

    static final String DISCOVERY = "DISCOVERY";

    private final JdbcTemplate jdbc;

    LifecycleFixtures(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Empties every table the tests write and puts the flags back to their seeded state. */
    void reset() {
        // TRUNCATE ... CASCADE reaches global_feature_flags through users; keep the migrated seed aside.
        jdbc.execute("CREATE TABLE IF NOT EXISTS test_global_flag_seed AS SELECT * FROM global_feature_flags");
        jdbc.execute("TRUNCATE feature_lifecycle_state, feature_lifecycle_transition, discovery_config,"
                + " discovery_scan, organization_feature_flags, org_type_feature_flags, users, organizations CASCADE");
        jdbc.execute("INSERT INTO global_feature_flags SELECT * FROM test_global_flag_seed ON CONFLICT DO NOTHING");
        jdbc.update("UPDATE global_feature_flags SET enabled = TRUE WHERE feature_key = ?", DISCOVERY);
        switchBaseline(false);
    }

    /** The FEATURE_LIFECYCLE_RECONCILE ops switch (baseline sweep). */
    void switchBaseline(boolean enabled) {
        jdbc.update("UPDATE global_feature_flags SET enabled = ? WHERE feature_key = 'FEATURE_LIFECYCLE_RECONCILE'",
                enabled);
    }

    /** An organization of {@code orgType} with {@code scans} discovery scans running. */
    long organization(String slug, String orgType, int scans) {
        long org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type) VALUES (?, ?, ?, ?)"
                + " RETURNING id", Long.class, slug, slug + ".test", slug, orgType);
        for (int i = 0; i < scans; i++) {
            runningScan(org, slug + "-scan-" + i);
        }
        return org;
    }

    void orgOverride(long org, String featureKey, boolean enabled, boolean adminLocked) {
        jdbc.update("INSERT INTO organization_feature_flags (organization_id, feature_key, enabled, admin_locked)"
                + " VALUES (?, ?, ?, ?)", org, featureKey, enabled, adminLocked);
    }

    void orgTypeDefault(String orgType, String featureKey, boolean enabled) {
        jdbc.update("INSERT INTO org_type_feature_flags (org_type, feature_key, enabled) VALUES (?, ?, ?)",
                orgType, featureKey, enabled);
    }

    /** A running discovery scan with its configuration. */
    void runningScan(long org, String requestId) {
        jdbc.update("INSERT INTO discovery_scan (request_id, organization_id, target_type, credential_xref, scope_key,"
                + " status, requested_at) VALUES (?, ?, 'AWS_ACM', 'cred', 'scope', 'RECEIVING', NOW())", requestId, org);
        jdbc.update("INSERT INTO discovery_config (organization_id, target_type, credential_xref, last_request_id,"
                + " status) VALUES (?, 'AWS_ACM', 'cred', ?, 'IN_PROGRESS')", org, requestId);
    }

    long runningScans(long org) {
        return count("SELECT COUNT(*) FROM discovery_scan WHERE organization_id = ?"
                + " AND status IN ('DISPATCHED', 'RECEIVING')", org);
    }

    long cancelledScans(long org) {
        return count("SELECT COUNT(*) FROM discovery_scan WHERE organization_id = ? AND status = 'CANCELLED'", org);
    }

    /** Every forced transition's id and status, oldest first. */
    List<Map<String, Object>> transitions() {
        return jdbc.queryForList("SELECT id, status FROM feature_lifecycle_transition ORDER BY id");
    }

    long newestTransitionId() {
        Long id = jdbc.queryForObject("SELECT MAX(id) FROM feature_lifecycle_transition", Long.class);
        return id == null ? 0 : id;
    }

    /** Makes every pending transition look abandoned by its after-commit run. */
    void ageTransitions() {
        jdbc.update("UPDATE feature_lifecycle_transition SET updated_at = NOW() - INTERVAL '10 minutes'");
    }

    long count(String sql, Object... args) {
        Long count = jdbc.queryForObject(sql, Long.class, args);
        return count == null ? 0 : count;
    }
}
