// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.security.Permissions;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The seed data V1 gives a new installation: the four open edition roles and nothing retired, the
 * organization- and platform-wide permissions only on the admin roles, and the platform ops flags
 * seeded as the services expect.
 */
@Testcontainers(disabledWithoutDocker = true)
class BaselineSeedPostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @BeforeAll
    static void migrate() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();
    }

    @Test
    void seedsExactlyTheFourOpenEditionRoles() throws SQLException {
        assertThat(strings("SELECT name FROM roles"))
                .containsExactlyInAnyOrder(Permissions.ROLE_SUPER_ADMIN, Permissions.ROLE_ORGANIZATION_ADMIN,
                        Permissions.ROLE_SECURITY_ANALYST, Permissions.ROLE_VIEWER);
    }

    @Test
    void seedsNoRetiredRows() throws SQLException {
        assertThat(strings("SELECT 'roles' FROM roles WHERE is_deleted UNION ALL "
                + "SELECT 'permissions' FROM permissions WHERE is_deleted UNION ALL "
                + "SELECT 'role_permissions' FROM role_permissions WHERE is_deleted")).isEmpty();
    }

    @Test
    void onlyTheAdminRolesCanManageTheOrganization() throws SQLException {
        assertThat(rolesHolding(Permissions.ORGANIZATION_MANAGE))
                .containsExactlyInAnyOrder(Permissions.ROLE_SUPER_ADMIN, Permissions.ROLE_ORGANIZATION_ADMIN);
    }

    @Test
    void onlySuperAdminAdministersFeatureFlags() throws SQLException {
        assertThat(rolesHolding(Permissions.FEATURE_FLAGS_ADMINISTER)).containsExactly(Permissions.ROLE_SUPER_ADMIN);
    }

    @Test
    void theFeatureLifecycleSwitchIsSeededOffAsAPlatformOpsFlag() throws SQLException {
        assertThat(strings("SELECT scope || '/' || category || '/' || enabled FROM global_feature_flags"
                + " WHERE feature_key = 'FEATURE_LIFECYCLE_RECONCILE'")).containsExactly("PLATFORM/PLATFORM/false");
    }

    private static List<String> rolesHolding(String permission) throws SQLException {
        return strings("SELECT r.name FROM role_permissions rp JOIN roles r ON r.id = rp.role_id "
                + "JOIN permissions p ON p.id = rp.permission_id WHERE p.name = '" + permission + "'");
    }

    private static List<String> strings(String sql) throws SQLException {
        List<String> values = new ArrayList<>();
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); Statement s = c.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            while (rs.next()) {
                values.add(rs.getString(1));
            }
        }
        return values;
    }
}
