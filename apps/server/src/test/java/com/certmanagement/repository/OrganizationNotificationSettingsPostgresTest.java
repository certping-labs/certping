// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The notification settings on PostgreSQL: every organization starts with nothing turned off, the flag is
 * seeded on with the organization type off, and the repository's reads and writes of the turned-off categories.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class OrganizationNotificationSettingsPostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @BeforeAll
    static void migrate() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();
    }

    @Autowired private OrganizationRepository organizations;
    @Autowired private JdbcTemplate jdbc;

    @Test
    void theFlagIsSeededOnGloballyAndOffForTheOrganizationType() {
        assertThat(jdbc.queryForObject("SELECT scope || ':' || category || ':' || enabled FROM global_feature_flags"
                + " WHERE feature_key = 'NOTIFICATION_PREFERENCES'", String.class)).isEqualTo("ORG:PLATFORM:true");
        assertThat(jdbc.queryForList("SELECT org_type || ':' || enabled FROM org_type_feature_flags"
                + " WHERE feature_key = 'NOTIFICATION_PREFERENCES' ORDER BY org_type", String.class))
                .containsExactly("B2B:false");
    }

    @Test
    void anOrganizationStartsWithNothingTurnedOff() {
        long org = organization();

        assertThat(organizations.findMutedNotificationCategories(org)).contains("");
        assertThat(jdbc.queryForObject("SELECT cardinality(muted_notification_categories) FROM organizations"
                + " WHERE id = ?", Integer.class, org)).isZero();
    }

    @Test
    void writesAndReadsTheCategoriesTurnedOffUnderTheRowLock() {
        long org = organization();
        long other = organization();

        assertThat(organizations.lockMutedNotificationCategories(org)).contains("");
        assertThat(organizations.updateMutedNotificationCategories(org, "CERTIFICATE_ACTIVITY,REPORTS")).isEqualTo(1);

        assertThat(organizations.findMutedNotificationCategories(org)).contains("CERTIFICATE_ACTIVITY,REPORTS");
        assertThat(jdbc.queryForObject("SELECT cardinality(muted_notification_categories) FROM organizations"
                + " WHERE id = ?", Integer.class, org)).isEqualTo(2);
        assertThat(organizations.findMutedNotificationCategories(other)).contains("");

        organizations.updateMutedNotificationCategories(org, "");
        assertThat(organizations.findMutedNotificationCategories(org)).contains("");
    }

    @Test
    void aDeletedOrUnknownOrganizationHasNoSettings() {
        long org = organization();
        jdbc.update("UPDATE organizations SET is_deleted = true WHERE id = ?", org);

        assertThat(organizations.findMutedNotificationCategories(org)).isEmpty();
        assertThat(organizations.lockMutedNotificationCategories(org)).isEmpty();
        assertThat(organizations.updateMutedNotificationCategories(org, "REPORTS")).isZero();
        assertThat(organizations.findMutedNotificationCategories(Long.MAX_VALUE)).isEmpty();
    }

    private long organization() {
        String name = "org-" + UUID.randomUUID();
        return jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type) VALUES (?, ?, ?, 'B2B')"
                + " RETURNING id", Long.class, name, name + ".example", name);
    }
}
