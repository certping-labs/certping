// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.application;

import com.certmanagement.audit.AuditAsyncWriter;
import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.support.auth.AuthenticatedUser;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationAuditAction;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.flywaydb.core.Flyway;
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
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An integration change's audit row is written in the change's own transaction and rolled back with it. A refused
 * change is the endpoint's to record (@AuditFailure).
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({IntegrationAuditService.class, AuditAsyncWriter.class,
        AuditEventStore.class, AuditRecorder.class, SupportAuditRecorder.class, JacksonAutoConfiguration.class,
        IntegrationAuditServicePostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class IntegrationAuditServicePostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:15-alpine");

    @TestConfiguration
    static class Beans {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }

        @Bean
        java.time.Clock clock() {
            return java.time.Clock.systemUTC();
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

    @Autowired private IntegrationAuditService integrationAudit;
    @Autowired private AuditEventStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private long organizationId;
    private int userId;

    @BeforeEach
    void seed() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL session_replication_role = replica");
            jdbc.execute("DELETE FROM audit_events");
        });
        store.createPartition(YearMonth.now(ZoneOffset.UTC));
        store.createPartition(YearMonth.now(ZoneOffset.UTC).plusMonths(1));
        jdbc.execute("DELETE FROM users");
        jdbc.execute("DELETE FROM organizations");
        organizationId = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Acme', 'acme.test', 'acme') RETURNING id",
                Long.class);
        userId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('alice@acme.test', 'Alice Admin', ?) RETURNING id", Integer.class, organizationId);
    }

    @Test
    void createUpdateAndDeleteEachGetOneRow() throws InterruptedException {
        for (IntegrationAuditAction action : List.of(IntegrationAuditAction.CREATED, IntegrationAuditAction.UPDATED,
                IntegrationAuditAction.DELETED)) {
            new TransactionTemplate(transactionManager).executeWithoutResult(status ->
                    integrationAudit.recordSuccess(integration(), action));
        }

        Thread.sleep(300);
        assertThat(jdbc.queryForList("SELECT event || ': ' || summary FROM audit_events ORDER BY id", String.class))
                .containsExactly("integration.created: Added the Slack integration",
                        "integration.updated: Changed the Slack integration",
                        "integration.deleted: Removed the Slack integration");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class)).isEqualTo(3);
        assertThat(jdbc.queryForList("SELECT audit_events::text FROM audit_events", String.class))
                .allSatisfy(row -> assertThat(row).doesNotContain("alice@acme.test"));
    }

    @Test
    void aRolledBackChangeLeavesNoRow() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            integrationAudit.recordSuccess(integration(), IntegrationAuditAction.CREATED);
            status.setRollbackOnly();
        });

        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class)).isZero();
    }

    @Test
    void theRowsNeedTheChangesOwnTransaction() {
        assertThatThrownBy(() -> integrationAudit.recordSuccess(integration(), IntegrationAuditAction.CREATED)).isInstanceOf(IllegalTransactionStateException.class);
    }

    private AuthenticatedUser user() {
        return new AuthenticatedUser((long) userId, "alice@acme.test", Long.toString(organizationId), "Acme",
                List.of(), List.of(), "PASSWORD");
    }

    private Integration integration() {
        Integration integration = new Integration(organizationId, IntegrationProvider.SLACK, Map.of(), Map.of(),
                (long) userId);
        ReflectionTestUtils.setField(integration, "id", 11L);
        return integration;
    }
}
