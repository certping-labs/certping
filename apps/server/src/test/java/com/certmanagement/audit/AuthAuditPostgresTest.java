// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.SignInAccount;
import com.certmanagement.service.audit.AuthAuditRecorder;
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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

/**
 * The sign-in events against PostgreSQL 15 with the real async writer: an SSO sign-in has exactly one
 * {@code audit_events} row, and the in-transaction writes (a password change, a completed reset) commit and
 * roll back with their change.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms", "certping.audit.async.retry-for=1s"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditAsyncWriter.class, AuditEventStore.class,
        AuditRecorder.class, AuthAuditRecorder.class, JacksonAutoConfiguration.class, AuthAuditPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuthAuditPostgresTest {

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

    @Autowired private AuthAuditRecorder authAudit;
    @Autowired private AuditEventStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private long organizationId;
    private int aliceId;
    private SignInAccount alice;

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
        aliceId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('alice@acme.test', 'Alice Admin', ?) RETURNING id", Integer.class, organizationId);
        alice = new SignInAccount(aliceId, organizationId, false);
        // An SSO callback: the /api interceptor never ran, so only the servlet request knows the client.
        RequestContextInterceptor.clearContext();
    }

    @AfterEach
    void clear() {
        RequestContextInterceptor.clearContext();
    }

    @Test
    void anSsoSignInHasExactlyOneRow() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status ->
                authAudit.signedIn(alice, AuthAuditRecorder.Method.OIDC, "org-acme-oidc"));

        await().atMost(Duration.ofSeconds(10)).until(() -> rows() == 1);
        await().during(Duration.ofMillis(300)).atMost(Duration.ofSeconds(2)).until(() -> rows() == 1);
        Map<String, Object> row = jdbc.queryForMap("SELECT event, visibility, actor_user_id, actor_label, summary,"
                + " auth_method FROM audit_events");
        assertThat(row).containsEntry("event", "auth.signed_in").containsEntry("visibility", "CUSTOMER")
                .containsEntry("actor_user_id", aliceId).containsEntry("actor_label", "Alice Admin")
                .containsEntry("summary", "Signed in with single sign-on").containsEntry("auth_method", "SSO");
    }

    @Test
    void aPasswordChangeCommitsAndRollsBackWithItsTransactionAndNeedsOne() {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        tx.executeWithoutResult(status -> authAudit.passwordChanged(alice));
        tx.executeWithoutResult(status -> {
            authAudit.passwordResetCompleted(alice);
            status.setRollbackOnly();
        });

        assertThat(jdbc.queryForList("SELECT event FROM audit_events", String.class))
                .containsExactly("auth.password_changed");
        assertThatThrownBy(() -> authAudit.passwordChanged(alice))
                .as("the change's own transaction is required")
                .isInstanceOf(IllegalTransactionStateException.class);
    }

    @Test
    void aRefusedSignInSurvivesTheRollbackOfTheSignInsTransaction() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            authAudit.signInFailed(alice, null, AuthAuditRecorder.Method.PASSWORD, null,
                    AuditReason.of("INVALID_CREDENTIALS"));
            authAudit.signedIn(alice, AuthAuditRecorder.Method.PASSWORD, null);
            status.setRollbackOnly();
        });

        await().atMost(Duration.ofSeconds(10)).until(() -> rows() == 1);
        assertThat(jdbc.queryForMap("SELECT event, outcome, error_code FROM audit_events"))
                .containsEntry("event", "auth.sign_in_failed").containsEntry("outcome", "FAILURE")
                .containsEntry("error_code", "INVALID_CREDENTIALS");
    }

    private int rows() {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM audit_events", Integer.class);
        return count == null ? 0 : count;
    }
}
