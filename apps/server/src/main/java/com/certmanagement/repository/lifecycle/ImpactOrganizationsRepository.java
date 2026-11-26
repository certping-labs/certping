// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Counts the distinct organizations across every kind a feature's switch-off affects, in one
 * {@code UNION ALL} statement: an organization holding records of two kinds counts once.
 */
@Repository
@RequiredArgsConstructor
public class ImpactOrganizationsRepository {

    private final NamedParameterJdbcTemplate jdbc;

    /**
     * @param kinds the organizations of each affected kind
     * @return distinct organizations across all of them; 0 for none
     */
    public long countDistinct(List<AffectedOrganizations> kinds) {
        if (kinds.isEmpty()) {
            return 0;
        }
        List<String> selects = new ArrayList<>(kinds.size());
        MapSqlParameterSource params = new MapSqlParameterSource();
        for (int arm = 0; arm < kinds.size(); arm++) {
            selects.add(bindArm(kinds.get(arm), "_k" + arm, params));
        }
        Long count = jdbc.queryForObject("SELECT COUNT(DISTINCT organization_id) FROM ("
                + String.join(" UNION ALL ", selects) + ") affected", params, Long.class);
        return count == null ? 0 : count;
    }

    /**
     * Gives one arm's named parameters a suffix of their own and binds them, so two kinds may use the
     * same name for different values (one kind's {@code :active} may be "ACTIVE" and another's "active").
     * The SQL comes only from this package's repositories, and a name is replaced only where it
     * stands as a parameter ({@code :name}, not a {@code ::cast} nor a longer name).
     */
    private static String bindArm(AffectedOrganizations kind, String suffix, MapSqlParameterSource into) {
        String sql = kind.selectSql();
        MapSqlParameterSource params = kind.params();
        for (String name : params.getParameterNames()) {
            Pattern parameter = Pattern.compile("(?<![:\\w]):" + Pattern.quote(name) + "(?!\\w)");
            sql = parameter.matcher(sql).replaceAll(Matcher.quoteReplacement(":" + name + suffix));
            into.addValue(name + suffix, params.getValue(name), params.getSqlType(name));
        }
        return sql;
    }
}
