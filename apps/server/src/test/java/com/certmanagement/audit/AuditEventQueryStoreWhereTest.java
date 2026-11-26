// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The customer WHERE clause: the literal visibility, and no organization only for a super admin. */
class AuditEventQueryStoreWhereTest {

    @Test
    void aCustomerQueryWithoutAnOrganizationThrows() {
        AuditEventQuery noOrganization = AuditEventQuery.builder().superAdmin(false).build();

        assertThatThrownBy(() -> AuditEventQueryStore.where(noOrganization, new MapSqlParameterSource()))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> AuditEventQueryStore.listStatement(noOrganization, null, 0, 10))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> AuditEventQueryStore.countStatement(noOrganization, 10))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aSuperAdminMayReadEveryOrganizationAndACustomerReadsTheirs() {
        MapSqlParameterSource params = new MapSqlParameterSource();

        assertThat(AuditEventQueryStore.where(AuditEventQuery.builder().superAdmin(true).build(), params))
                .isEqualTo("WHERE visibility = 'CUSTOMER' AND category <> 'ACCESS'");
        assertThat(AuditEventQueryStore.where(AuditEventQuery.builder().organizationId(7L).build(), params))
                .isEqualTo("WHERE visibility = 'CUSTOMER' AND organization_id = :organizationId AND category <> 'ACCESS'");
        assertThat(params.getValue("organizationId")).isEqualTo(7L);
    }

    @Test
    void sensitiveReadsAreLeftOutUnlessAskedForByCategory() {
        MapSqlParameterSource params = new MapSqlParameterSource();

        String access = AuditEventQueryStore.where(AuditEventQuery.builder().organizationId(7L)
                .category(AuditCategory.ACCESS).build(), params);
        String certificates = AuditEventQueryStore.where(AuditEventQuery.builder().organizationId(7L)
                .category(AuditCategory.CERTIFICATES).build(), new MapSqlParameterSource());

        assertThat(access).contains("category = :category").doesNotContain("<> 'ACCESS'");
        assertThat(params.getValue("category")).isEqualTo("ACCESS");
        assertThat(certificates).contains("category = :category").doesNotContain("<> 'ACCESS'");
    }

    @Test
    void onlyAReferenceSearchAcrossEveryOrganizationMatchesTheIdBeforeOrdering() {
        AuditEventQuery platform = AuditEventQuery.builder().view(AuditTrailView.PLATFORM).superAdmin(true).build();

        assertThat(AuditEventQueryStore.listStatement(platform.toBuilder().requestId("req-1").build(), null, 0, 21)
                .sql()).startsWith("WITH matched AS MATERIALIZED (SELECT ").contains("request_id = :requestId")
                .endsWith(") SELECT * FROM matched ORDER BY occurred_at DESC, id DESC LIMIT :limit");
        assertThat(AuditEventQueryStore.listStatement(platform.toBuilder().correlationId("c").build(), null, 0, 21)
                .sql()).startsWith("WITH matched");
        assertThat(AuditEventQueryStore.listStatement(platform.toBuilder().requestId("req-1").organizationId(7L)
                .build(), null, 0, 21).sql()).as("one organization: its index bounds the scan").startsWith("SELECT id,");
        assertThat(AuditEventQueryStore.listStatement(platform, null, 0, 21).sql()).startsWith("SELECT id,");
    }
}
