// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The impact preview's aggregate SQL on the migrated schema: one UNION counts an organization once
 * across kinds, within each scope.
 */
@Testcontainers(disabledWithoutDocker = true)
class ImpactOrganizationsPostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    private static JdbcTemplate jdbc;
    private static AccessLifecycleRepository access;
    private static ImpactOrganizationsRepository impactOrganizations;
    private static long acme;
    private static long beta;
    private static long delta;

    @BeforeAll
    static void migrateAndSeed() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
        DriverManagerDataSource dataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        jdbc = new JdbcTemplate(dataSource);
        NamedParameterJdbcTemplate named = new NamedParameterJdbcTemplate(dataSource);
        access = new AccessLifecycleRepository(named);
        impactOrganizations = new ImpactOrganizationsRepository(named);

        acme = organization("acme");
        beta = organization("beta");
        delta = organization("delta");
        credential(acme, "DNS", "ACTIVE");
        credential(acme, "DEPLOYMENT", "ACTIVE");
        credential(beta, "DNS", "ACTIVE");
        credential(delta, "DNS", "INACTIVE");
    }

    @Test
    void anOrganizationInTwoKindsCountsOnce() {
        List<AffectedOrganizations> kinds = List.of(
                access.activeCredentialOrganizations(ImpactScope.everyOrganization()),
                access.activeCredentialOrganizations(ImpactScope.organization(acme)));

        // acme and beta hold active credentials; delta's is inactive.
        assertThat(impactOrganizations.countDistinct(kinds)).isEqualTo(2);
        assertThat(access.activeCredentialsImpact(ImpactScope.everyOrganization()))
                .isEqualTo(new RecordImpact(3, 2));
    }

    @Test
    void theUnionRespectsTheScope() {
        assertThat(impactOrganizations.countDistinct(List.of(
                access.activeCredentialOrganizations(ImpactScope.organization(beta)),
                access.activeIntegrationOrganizations(ImpactScope.organization(beta)))))
                .isEqualTo(1);
        assertThat(impactOrganizations.countDistinct(List.of(
                access.activeCredentialOrganizations(ImpactScope.orgType("B2B")))))
                .isEqualTo(2);
        assertThat(impactOrganizations.countDistinct(List.of())).isZero();
    }

    @Test
    void kindsBindingTheSameParameterNameToDifferentValuesKeepTheirOwn() {
        CertificateLifecycleRepository certificates =
                new CertificateLifecycleRepository(new NamedParameterJdbcTemplate(jdbc));

        // :caProvider is DIGICERT in one arm and GLOBALSIGN in the other, :scopeOrganizationId null in two
        // arms and delta's id in the third; nothing matches, but each arm must bind its own values.
        assertThat(impactOrganizations.countDistinct(List.of(
                certificates.autoRenewOrganizations(ImpactScope.everyOrganization(),
                        CertificateLifecycleRepository.AutoRenewScope.onCa("DIGICERT")),
                certificates.autoRenewOrganizations(ImpactScope.everyOrganization(),
                        CertificateLifecycleRepository.AutoRenewScope.onCa("GLOBALSIGN")),
                access.activeCredentialOrganizations(ImpactScope.organization(delta)))))
                .isZero();
    }

    private static long organization(String slug) {
        return jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type) VALUES (?, ?, ?, 'B2B')"
                + " RETURNING id", Long.class, slug, slug + ".test", slug);
    }

    private static void credential(long organizationId, String type, String status) {
        jdbc.update("INSERT INTO credential_references (credential_xref, organization_id, provider, type, status,"
                + " secret_handle, is_deleted) VALUES (?, ?, 'CLOUDFLARE', ?, ?, 'https://kv.test/secrets/x', false)",
                "cred-" + System.nanoTime(), organizationId, type, status);
    }
}
