// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import com.certmanagement.repository.lifecycle.RecordImpact;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Aggregate counts of an organization's access configuration the feature lifecycle reports but never
 * changes in bulk: active credentials (certificates depend on them) and active integrations (paging and
 * chat delivery).
 */
@Repository
@RequiredArgsConstructor
public class AccessLifecycleRepository {

    private static final String ACTIVE_CREDENTIALS =
            " FROM credential_references WHERE status = 'ACTIVE' AND is_deleted = FALSE";
    private static final String ORG_FILTER = " AND organization_id = :organizationId";
    private static final String ACTIVE_INTEGRATIONS =
            " FROM integrations WHERE status = 'ACTIVE' AND deleted_at IS NULL";
    private static final String INTEGRATION_ORGANIZATION = "org_id";

    private final NamedParameterJdbcTemplate jdbc;

    public long countActiveCredentials(long organizationId) {
        return count("SELECT COUNT(*)" + ACTIVE_CREDENTIALS + ORG_FILTER, organizationId);
    }

    public RecordImpact activeCredentialsImpact(ImpactScope scope) {
        return impact(ACTIVE_CREDENTIALS, scope);
    }

    public AffectedOrganizations activeCredentialOrganizations(ImpactScope scope) {
        return organizations(ACTIVE_CREDENTIALS, scope);
    }

    public long countActiveIntegrations(long organizationId) {
        Long count = jdbc.queryForObject("SELECT COUNT(*)" + ACTIVE_INTEGRATIONS + " AND org_id = :organizationId",
                new MapSqlParameterSource("organizationId", organizationId), Long.class);
        return count == null ? 0 : count;
    }

    public RecordImpact activeIntegrationsImpact(ImpactScope scope) {
        return jdbc.queryForObject("SELECT COUNT(*) AS records, COUNT(DISTINCT org_id) AS organizations"
                        + ACTIVE_INTEGRATIONS + scope.filter(INTEGRATION_ORGANIZATION),
                scope.bind(new MapSqlParameterSource()),
                (rows, rowNum) -> new RecordImpact(rows.getLong("records"), rows.getLong("organizations")));
    }

    public AffectedOrganizations activeIntegrationOrganizations(ImpactScope scope) {
        return new AffectedOrganizations("SELECT org_id AS organization_id" + ACTIVE_INTEGRATIONS
                + scope.filter(INTEGRATION_ORGANIZATION), scope.bind(new MapSqlParameterSource()));
    }

    private long count(String sql, long organizationId) {
        Long count = jdbc.queryForObject(sql, new MapSqlParameterSource("organizationId", organizationId), Long.class);
        return count == null ? 0 : count;
    }

    private static AffectedOrganizations organizations(String fromWhere, ImpactScope scope) {
        return new AffectedOrganizations("SELECT organization_id" + fromWhere + scope.filter("organization_id"),
                scope.bind(new MapSqlParameterSource()));
    }

    private RecordImpact impact(String fromWhere, ImpactScope scope) {
        return jdbc.queryForObject("SELECT COUNT(*) AS records, COUNT(DISTINCT organization_id) AS organizations"
                        + fromWhere + scope.filter("organization_id"),
                scope.bind(new MapSqlParameterSource()),
                (rows, rowNum) -> new RecordImpact(rows.getLong("records"), rows.getLong("organizations")));
    }
}
