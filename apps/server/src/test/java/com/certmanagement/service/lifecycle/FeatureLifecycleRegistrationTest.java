// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.repository.lifecycle.AccessLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.DiscoveryLifecycleRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Every ORG-scope flag — one an organization admin may switch off — has consciously decided what
 * switching it off must clear: it has a {@link FeatureLifecycle} or is listed in
 * {@link FeatureLifecycleRegistry#NOTHING_TO_CLEAR}. The scopes come from the migrated catalog, so a
 * new ORG-scope flag seeded by a migration fails here until that decision is made.
 */
@Testcontainers(disabledWithoutDocker = true)
class FeatureLifecycleRegistrationTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
    }

    /** The registry exactly as production wires it, over mocked storage. */
    static FeatureLifecycleRegistry productionRegistry() {
        FeatureLifecycleConfiguration configuration = new FeatureLifecycleConfiguration();
        CertificateLifecycleRepository certificates = mock(CertificateLifecycleRepository.class);
        AccessLifecycleRepository access = mock(AccessLifecycleRepository.class);
        return new FeatureLifecycleRegistry(List.of(
                configuration.certificateRenewalLifecycle(certificates),
                configuration.integrationsLifecycle(access),
                configuration.letsEncryptLifecycle(certificates),
                configuration.digicertLifecycle(certificates),
                configuration.globalSignLifecycle(certificates),
                configuration.certificateIssuanceLifecycle(certificates),
                configuration.credentialsLifecycle(access),
                new CertificateDeploymentLifecycle(certificates),
                new DiscoveryLifecycle(mock(DiscoveryLifecycleRepository.class))));
    }

    @Test
    void everyOrgScopeFlagIsRegisteredOrListedAsNothingToClear() throws SQLException {
        Set<String> decided = new HashSet<>(productionRegistry().registeredFeatureKeys());
        decided.addAll(FeatureLifecycleRegistry.NOTHING_TO_CLEAR);

        List<String> orgScoped = orgScopedFlags();

        assertThat(orgScoped).isNotEmpty();
        assertThat(decided)
                .as("ORG-scope flags without a FeatureLifecycle or a NOTHING_TO_CLEAR entry")
                .containsAll(orgScoped);
    }

    private static List<String> orgScopedFlags() throws SQLException {
        List<String> keys = new ArrayList<>();
        try (Connection connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT feature_key FROM global_feature_flags WHERE scope = 'ORG' ORDER BY feature_key")) {
            while (rows.next()) {
                keys.add(rows.getString(1));
            }
        }
        return keys;
    }
}
