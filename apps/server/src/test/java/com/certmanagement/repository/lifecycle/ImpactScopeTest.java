// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ImpactScopeTest {

    @Test
    void everyOrganizationAddsNoCondition() {
        assertThat(ImpactScope.everyOrganization().filter("udc.organization_id")).isEmpty();
    }

    @Test
    void oneOrganizationFiltersOnItsId() {
        ImpactScope scope = ImpactScope.organization(7L);

        assertThat(scope.filter("organization_id")).isEqualTo(" AND organization_id = :scopeOrganizationId");
        assertThat(scope.bind(new MapSqlParameterSource()).getValue("scopeOrganizationId")).isEqualTo(7L);
    }

    @Test
    void anOrgTypeFiltersOnTheOrganizationsOfThatType() {
        ImpactScope scope = ImpactScope.orgType("B2B");

        assertThat(scope.filter("udc.organization_id")).isEqualTo(" AND udc.organization_id IN (SELECT scope_org.id"
                + " FROM organizations scope_org WHERE scope_org.org_type = :scopeOrgType)");
        assertThat(scope.bind(new MapSqlParameterSource()).getValue("scopeOrgType")).isEqualTo("B2B");
    }

    @Test
    void anOrganizationAndAnOrgTypeAreMutuallyExclusiveAndTheTypeIsValidated() {
        assertThatThrownBy(() -> new ImpactScope(7L, "B2B")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ImpactScope.orgType("b2b; DROP TABLE x")).isInstanceOf(IllegalArgumentException.class);
    }
}
