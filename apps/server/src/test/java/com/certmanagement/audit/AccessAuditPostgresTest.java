// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.AccessAuditRecorder;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.audit.OrganizationAuditRecorder;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Clock;
import java.time.Duration;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * The access-control, SSO, organization, feature and data-retention events against PostgreSQL 15 with the real
 * async writer: each action has exactly one {@code audit_events} row, a rolled-back change leaves no row, no
 * column of any row holds the member's name or email, and the rows are written in the change's own
 * transaction.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms", "certping.audit.async.retry-for=1s"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditAsyncWriter.class, AuditEventStore.class,
        AuditRecorder.class, AccessAuditRecorder.class, OrganizationAuditRecorder.class,
        FeatureFlagChangeAudit.class, JacksonAutoConfiguration.class, AccessAuditPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AccessAuditPostgresTest {

    private static final String EMAIL = "alice.member@acme.test";
    private static final String NAME = "Alice Member";

    @Container
    static final PostgreSQLContainer POSTGRES = AuditPostgres.container();

    @TestConfiguration
    static class Beans {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }

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

    @Autowired private AccessAuditRecorder accessAudit;
    @Autowired private OrganizationAuditRecorder organizationAudit;
    @Autowired private FeatureFlagChangeAudit featureAudit;
    @Autowired private AuditEventStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private long organizationId;
    private int adminId;
    private User alice;
    private Organization acme;

    @BeforeEach
    void seed() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        YearMonth now = YearMonth.now(ZoneOffset.UTC);
        store.createPartition(now);
        store.createPartition(now.plusMonths(1));
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
        organizationId = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id",
                Long.class);
        adminId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('bob.admin@acme.test', 'Bob Admin', ?) RETURNING id", Integer.class, organizationId);
        int aliceId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES (?, ?, ?) RETURNING id", Integer.class, EMAIL, NAME, organizationId);
        acme = Organization.builder().id(organizationId).name("Acme").domain("acme.test").build();
        alice = User.builder().id(aliceId).email(EMAIL).displayName(NAME).organization(acme)
                .roles(Set.of(Role.builder().id(2L).name("VIEWER").build())).build();
        GatewayRequestContext.set(adminId, String.valueOf(organizationId), "req-1", "bob.admin@acme.test");
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    @Test
    void everyActionHasExactlyOneRowAndTheBackfillCopiesNothingMore() {
        Role editor = Role.builder().id(40L).name("DOMAIN_EDITOR").organization(acme)
                .permissions(Set.of(Permission.builder().name("domains:view").build())).build();

        inTransaction(() -> {
            accessAudit.memberCreated(alice, alice.getRoles(), null, "LOCAL", null, AccessAuditRecorder.Actor.REQUEST);
            accessAudit.memberEmailChanged(alice);
            accessAudit.memberRolesChanged(alice, Set.of(), alice.getRoles(), List.of());
            accessAudit.memberDisabled(alice, alice.getRoles(), null, AccessAuditRecorder.Actor.REQUEST);
            accessAudit.memberDeleted(alice, alice.getRoles());
            accessAudit.roleCreated(editor);
            accessAudit.ssoRolesAssigned(alice, alice.getRoles(), "DEFAULT_ROLE", "org-1-oidc");
            organizationAudit.organizationCreated(acme);
            organizationAudit.organizationUpdated(organizationId, true, "acme.test", "acme.example", null, null);
            featureAudit.recordOrganization(5L, organizationId, "PQC_READINESS", null,
                    new FeatureFlagChangeAudit.OverrideState(false, false), null);
            featureAudit.recordPlatformTransition(organizationId, "CERTIFICATE_DEPLOYMENT", true,
                    List.of(Map.of("kind", "DEPLOYMENTS", "label", "deployments", "count", 12)), adminId);
            organizationAudit.recordsPurged(organizationId, 30, 4);
            organizationAudit.retentionChanged(organizationId, null, 14);
        });

        // Nothing else writes a copy: had it, it would land here within the writer's flush interval.
        await().during(Duration.ofMillis(400)).atMost(Duration.ofSeconds(3)).until(() -> true);
        assertThat(jdbc.queryForList("SELECT event FROM audit_events ORDER BY id", String.class)).containsExactly(
                "member.created", "member.email_changed", "member.roles_changed", "member.disabled", "member.deleted",
                "role.created", "member.sso_roles_assigned", "organization.created", "organization.updated",
                "feature.changed", "feature.paused", "data_retention.purged", "data_retention.changed");
        assertThat(count("SELECT count(*) FROM audit_events")).isEqualTo(13);

        // The member is named by id only; the actor (Bob) is the only person a row names.
        assertThat(jdbc.queryForList("SELECT audit_events::text FROM audit_events", String.class))
                .allSatisfy(row -> assertThat(row).doesNotContain(EMAIL).doesNotContain(NAME)
                        .doesNotContain("Acme Corp"));
        assertThat(jdbc.queryForList("SELECT DISTINCT actor_label FROM audit_events WHERE actor_type = 'USER'",
                String.class)).containsExactly("Bob Admin");
        assertThat(jdbc.queryForMap("SELECT actor_type, actor_job FROM audit_events WHERE event = 'feature.paused'"))
                .containsEntry("actor_type", "SYSTEM").containsEntry("actor_job", "feature-lifecycle-transitions");
    }

    @Test
    void aRolledBackChangeLeavesNeitherRow() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            accessAudit.memberDeleted(alice, alice.getRoles());
            status.setRollbackOnly();
        });

        await().during(Duration.ofMillis(300)).atMost(Duration.ofSeconds(2)).until(() -> true);
        assertThat(count("SELECT count(*) FROM audit_events")).isZero();
    }

    @Test
    void theRowsNeedTheChangesOwnTransaction() {
        assertThatThrownBy(() -> accessAudit.memberDeleted(alice, alice.getRoles()))
                .as("written in the change's transaction, which is required")
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThatThrownBy(() -> organizationAudit.recordsPurged(organizationId, 30, 1))
                .isInstanceOf(IllegalTransactionStateException.class);
    }

    private void inTransaction(Runnable work) {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> work.run());
    }

    private int count(String sql) {
        Integer count = jdbc.queryForObject(sql, Integer.class);
        return count == null ? 0 : count;
    }
}
