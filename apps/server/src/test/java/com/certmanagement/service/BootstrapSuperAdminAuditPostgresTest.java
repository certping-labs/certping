// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** The boot-time SUPER_ADMIN bootstrap and its audit row, on real PostgreSQL with every migration. */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {
        "spring.jpa.hibernate.ddl-auto=none",
        "spring.flyway.enabled=false",
        "app.bootstrap-super-admin.username=boot_admin",
        "app.bootstrap-super-admin.email=boot_admin@certping.test",
        "app.bootstrap-super-admin.password=" + BootstrapSuperAdminAuditPostgresTest.PASSWORD,
        "app.bootstrap-super-admin.display-name=Boot Admin"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AdminUserService.class, PasswordPolicy.class, LoginAttemptService.class, JacksonAutoConfiguration.class,
        com.certmanagement.service.audit.AccessAuditRecorder.class, com.certmanagement.audit.AuditRecorder.class,
        com.certmanagement.audit.AuditEventStore.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class BootstrapSuperAdminAuditPostgresTest {

    @MockitoBean private com.certmanagement.audit.AuditAsyncWriter auditAsyncWriter;

    static final String PASSWORD = "Bootstrap-Secret-4821";

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
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
    }

    @MockitoBean private PasswordEncoder passwordEncoder;
    @MockitoBean private JwtTokenProvider jwtTokenProvider;
    @MockitoBean private RefreshTokenService refreshTokenService;
    @MockitoBean private PermissionGrantPolicy grantPolicy;
    /** Sign-in events are not under test here; AuthAuditRecorderTest and AuthAuditPostgresTest cover them. */
    @MockitoBean private AuthAuditRecorder authAuditRecorder;

    @Autowired private AdminUserService adminUserService;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    @BeforeEach
    void clean() {
        when(passwordEncoder.encode(anyString())).thenReturn("hashed-password");
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        jdbc.execute("DELETE FROM user_roles");
        jdbc.execute("DELETE FROM user_permissions");
        jdbc.execute("DELETE FROM users");
    }

    @Test
    void bootCreatesTheAdminAndExactlyOneAuditRow() {
        adminUserService.ensureBootstrapSuperAdmin();

        Long userId = jdbc.queryForObject("SELECT id FROM users WHERE username = 'boot_admin'", Long.class);

        // A platform row (staff have no customer trail), CertPing acting.
        Map<String, Object> event = jdbc.queryForMap("SELECT event, visibility, actor_type, actor_job, "
                + "resource_ref, organization_id FROM audit_events");
        assertThat(event).containsEntry("event", "member.created").containsEntry("visibility", "INTERNAL")
                .containsEntry("actor_type", "SYSTEM").containsEntry("actor_job", "bootstrap")
                .containsEntry("resource_ref", userId.toString()).containsEntry("organization_id", null);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class)).isOne();
        assertThat(jdbc.queryForObject("SELECT audit_events::text FROM audit_events", String.class))
                .doesNotContain("boot_admin").doesNotContain(PASSWORD).doesNotContain("hashed-password");
    }

    @Test
    void aSecondBootWithTheAdminPresentWritesNoRow() {
        adminUserService.ensureBootstrapSuperAdmin();
        adminUserService.ensureBootstrapSuperAdmin();

        assertThat(jdbc.queryForObject("SELECT count(*) FROM users WHERE username = 'boot_admin'", Integer.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class)).isEqualTo(1);
    }

    @Test
    void theAuditRowIsWrittenInTheSameTransactionAsTheAdmin() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            adminUserService.ensureBootstrapSuperAdmin();
            status.setRollbackOnly();
        });

        assertThat(jdbc.queryForObject("SELECT count(*) FROM users", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class)).isZero();
    }
}
