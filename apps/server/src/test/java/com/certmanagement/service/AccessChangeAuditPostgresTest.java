// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.role.CreateRoleRequest;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.PermissionGrantPolicy;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Access-change audit rows on real PostgreSQL, through the Spring proxies: written before the
 * change commits, in its transaction, so a rolled-back change leaves no row.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ImportAutoConfiguration(JacksonAutoConfiguration.class)
@Import({RoleManagementService.class, PermissionFeatureVisibility.class,
        com.certmanagement.service.audit.AccessAuditRecorder.class, com.certmanagement.audit.AuditRecorder.class,
        com.certmanagement.audit.AuditEventStore.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AccessChangeAuditPostgresTest {

    @MockitoBean private com.certmanagement.audit.AuditAsyncWriter auditAsyncWriter;

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

    @MockitoBean private PermissionGrantPolicy grantPolicy;
    /** No feature is off, so permission visibility hides nothing and saves keep their full set. */
    @MockitoBean private FeatureFlagService featureFlagService;
    @Autowired private RoleManagementService roles;
    @Autowired private com.certmanagement.service.audit.AccessAuditRecorder accessAudit;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private long organizationId;
    private int actorId;

    @BeforeEach
    void seed() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM roles WHERE organization_id IS NOT NULL");
        jdbc.execute("DELETE FROM organizations");
        organizationId = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id",
                Long.class);
        actorId = jdbc.queryForObject("INSERT INTO users (email, organization_id) VALUES ('admin@acme.test', ?) RETURNING id",
                Integer.class, organizationId);
        GatewayRequestContext.set(actorId, String.valueOf(organizationId), "req-1", "admin@acme.test");
    }

    @AfterEach
    void clearContext() {
        GatewayRequestContext.clear();
    }

    @Test
    void aCommittedChangeHasItsRowWithTheActorAndTheAfterSet() {
        roles.createRole(domainEditor(), organizationId);

        long roleId = jdbc.queryForObject("SELECT id FROM roles WHERE name = 'DOMAIN_EDITOR'", Long.class);
        Map<String, Object> event = jdbc.queryForMap("SELECT event, summary, actor_user_id, organization_id, "
                + "resource_id, outcome, details::text AS details FROM audit_events");
        assertThat(event).containsEntry("event", "role.created")
                .containsEntry("summary", "Created the role 'DOMAIN_EDITOR'")
                .containsEntry("actor_user_id", actorId).containsEntry("organization_id", organizationId)
                .containsEntry("resource_id", roleId).containsEntry("outcome", "SUCCESS");
        assertThat((String) event.get("details")).contains("certificate:read").contains("certificate:renew");
    }

    @Test
    void aRolledBackChangeLeavesNoRow() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            roles.createRole(domainEditor(), organizationId);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_events", Integer.class)).isOne();
            status.setRollbackOnly();
        });

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM roles WHERE name = 'DOMAIN_EDITOR'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_events", Integer.class)).isZero();
    }

    @Test
    void recordingOutsideATransactionIsRefused() {
        com.certmanagement.entity.Role role = com.certmanagement.entity.Role.builder().id(1L).name("X")
                .organization(com.certmanagement.entity.Organization.builder().id(organizationId).build()).build();
        assertThatThrownBy(() -> accessAudit.roleDeleted(role, java.util.List.of(), 0))
                .isInstanceOf(IllegalTransactionStateException.class);
    }

    private static CreateRoleRequest domainEditor() {
        return CreateRoleRequest.builder().name("domain_editor")
                .permissionNames(Set.of("certificate:read", "certificate:renew")).build();
    }
}
