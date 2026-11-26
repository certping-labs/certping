// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

/**
 * The organizations holding one kind's affected records, as a query that selects one
 * {@code organization_id} column. {@link ImpactOrganizationsRepository} unions several of them to
 * count the distinct organizations across kinds in one statement.
 *
 * <p>Only the repositories of this package build one (the constructor is package-private): the SQL
 * is spliced into another statement, so it may never come from a caller.
 */
public final class AffectedOrganizations {

    private final String selectSql;
    private final MapSqlParameterSource params;

    AffectedOrganizations(String selectSql, MapSqlParameterSource params) {
        this.selectSql = selectSql;
        this.params = params;
    }

    /** {@code SELECT <organization column> AS organization_id FROM ... WHERE ...}. */
    String selectSql() {
        return selectSql;
    }

    MapSqlParameterSource params() {
        return params;
    }
}
