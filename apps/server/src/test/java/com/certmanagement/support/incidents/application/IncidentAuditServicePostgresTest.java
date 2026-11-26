// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.application;

import com.certmanagement.audit.AuditAsyncWriter;
import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.incidents.domain.Incident;
import com.certmanagement.support.incidents.domain.IncidentCreationSource;
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

import java.time.Duration;
import java.time.YearMonth;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * An incident's audit row is written in the transaction that stored it, and rolled back with it. CertPing's own
 * failed incident
 * is a failure row through the async writer; a member's refused one is the endpoint's to record.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({IncidentAuditService.class, AuditAsyncWriter.class,
        AuditEventStore.class, AuditRecorder.class, SupportAuditRecorder.class, JacksonAutoConfiguration.class,
        IncidentAuditServicePostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class IncidentAuditServicePostgresTest {

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

    @Autowired private IncidentAuditService incidentAudit;
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
    void aTriggerGetsOneRowInTheSameTransaction() throws InterruptedException {
        // The member's request raising it.
        GatewayRequestContext.set(userId, Long.toString(organizationId), "req-1", "alice@acme.test");
        try {
            new TransactionTemplate(transactionManager).executeWithoutResult(status ->
                    incidentAudit.recordSuccess(incident(IncidentCreationSource.PUBLIC_API)));
        } finally {
            GatewayRequestContext.clear();
        }

        Thread.sleep(300);
        assertThat(jdbc.queryForList("SELECT event || ' ' || summary || ' ' || actor_type FROM audit_events",
                String.class))
                .containsExactly("incident.triggered Raised an incident in PagerDuty USER");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class)).isOne();
    }

    @Test
    void anIncidentCertPingRaisedIsCertPingsRow() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status ->
                incidentAudit.recordSuccess(incident(IncidentCreationSource.INTERNAL_API)));

        assertThat(jdbc.queryForMap("SELECT actor_type, actor_job, actor_label, ip_address FROM audit_events"))
                .containsEntry("actor_type", "SYSTEM").containsEntry("actor_job", "integration-dispatch")
                .containsEntry("actor_label", "CertPing (automatic)").containsEntry("ip_address", null);
    }

    @Test
    void aRolledBackIncidentLeavesNoRow() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            incidentAudit.recordSuccess(incident(IncidentCreationSource.PUBLIC_API));
            status.setRollbackOnly();
        });

        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class)).isZero();
    }

    @Test
    void certPingsOwnFailureIsRecordedAfterTheRollbackWithASafeReason() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            incidentAudit.recordFailure(organizationId, IncidentCreationSource.INTERNAL_API,
                    IntegrationProvider.PAGERDUTY,
                    new ApiException(504, "PAGERDUTY_REQUEST_TIMEOUT", "timeout talking to api.pagerduty.test"));
            // A member's refusal is the endpoint's to record (@AuditFailure): nothing here.
            incidentAudit.recordFailure(organizationId, IncidentCreationSource.PUBLIC_API,
                    IntegrationProvider.PAGERDUTY, new ApiException(404, "INTEGRATION_NOT_FOUND", "missing"));
            status.setRollbackOnly();
        });

        await().atMost(Duration.ofSeconds(10)).until(() -> jdbc.queryForObject(
                "SELECT count(*) FROM audit_events", Integer.class) == 1);
        assertThat(jdbc.queryForMap("SELECT outcome, error_code, actor_type FROM audit_events"))
                .containsEntry("outcome", "FAILURE").containsEntry("error_code", "INTEGRATION_DELIVERY_FAILED")
                .containsEntry("actor_type", "SYSTEM");
        assertThat(jdbc.queryForObject("SELECT audit_events::text FROM audit_events", String.class))
                .doesNotContain("pagerduty.test");
    }

    @Test
    void theRowsNeedTheIncidentsOwnTransaction() {
        assertThatThrownBy(() -> incidentAudit.recordSuccess(incident(IncidentCreationSource.PUBLIC_API))).isInstanceOf(IllegalTransactionStateException.class);
    }

    private Incident incident(IncidentCreationSource source) {
        Incident incident = new Incident(organizationId,
                source == IncidentCreationSource.PUBLIC_API ? (long) userId : null, source,
                IntegrationProvider.PAGERDUTY, null, "summary", "ext-id", "INC-1", "https://incidents.test/1");
        ReflectionTestUtils.setField(incident, "id", 33L);
        return incident;
    }
}
