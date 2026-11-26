// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.sql.Types;
import java.util.Set;

/**
 * Which organizations an impact preview counts: every one, one organization, or every organization
 * of one type (an org-type default change). At most one of the two filters is set.
 */
public record ImpactScope(Long organizationId, String orgType) {

    private static final Set<String> ORG_TYPES = Set.of("B2B");

    public ImpactScope {
        if (organizationId != null && orgType != null) {
            throw new IllegalArgumentException("organizationId and orgType are mutually exclusive");
        }
        if (orgType != null && !ORG_TYPES.contains(orgType)) {
            throw new IllegalArgumentException("orgType must be B2B");
        }
    }

    public static ImpactScope everyOrganization() {
        return new ImpactScope(null, null);
    }

    public static ImpactScope organization(long organizationId) {
        return new ImpactScope(organizationId, null);
    }

    public static ImpactScope orgType(String orgType) {
        return new ImpactScope(null, orgType);
    }

    /**
     * The SQL condition (starting with " AND", or empty) restricting {@code organizationColumn} to this
     * scope. Appended only when set, so a generic prepared-statement plan keeps its index.
     */
    String filter(String organizationColumn) {
        if (organizationId != null) {
            return " AND " + organizationColumn + " = :scopeOrganizationId";
        }
        if (orgType != null) {
            return " AND " + organizationColumn
                    + " IN (SELECT scope_org.id FROM organizations scope_org WHERE scope_org.org_type = :scopeOrgType)";
        }
        return "";
    }

    /** Binds the scope's parameters onto {@code params}. */
    MapSqlParameterSource bind(MapSqlParameterSource params) {
        return params.addValue("scopeOrganizationId", organizationId, Types.BIGINT)
                .addValue("scopeOrgType", orgType, Types.VARCHAR);
    }
}
