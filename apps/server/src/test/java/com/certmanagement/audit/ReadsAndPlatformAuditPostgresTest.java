// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.interceptor.AuditInterceptor;
import com.certmanagement.security.GatewayRequestContext;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.servlet.HandlerMapping;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Against PostgreSQL 15 with the real request interceptor and async writer:
 * <ul>
 *   <li>a page load (GET) leaves no row, while a change request keeps its one internal {@code api.request}
 *       row;</li>
 *   <li>a sensitive read polled many times in 15 minutes is one access row, and another target is another.</li>
 * </ul>
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms", "certping.audit.async.retry-for=1s"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditAsyncWriter.class, AuditEventStore.class,
        AuditRecorder.class, AuditedReads.class,
        JacksonAutoConfiguration.class, ReadsAndPlatformAuditPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class ReadsAndPlatformAuditPostgresTest {

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

    /** The endpoints whose annotations the reads are recorded from. */
    static class Endpoints {
        @AuditedRead(value = AuditEventType.ACCESS_AGENT_CONNECTION_VIEWED, target = "#organizationId",
                organization = "#organizationId")
        public void connectionString(Long organizationId) {
        }

        @AuditedRead(AuditEventType.ACCESS_CBOM_DOWNLOADED)
        public void cbom() {
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

    @Autowired private AuditRecorder recorder;
    @Autowired private AuditedReads reads;
    @Autowired private AuditEventStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private AuditInterceptor interceptor;
    private long organizationId;
    private long otherOrganizationId;
    private int adminId;
    private int rootId;

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
        otherOrganizationId = jdbc.queryForObject(
                "INSERT INTO organizations (name, domain, slug) VALUES ('Beta', 'beta.test', 'beta') RETURNING id",
                Long.class);
        adminId = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) "
                + "VALUES ('bob.admin@acme.test', 'Bob Admin', ?) RETURNING id", Integer.class, organizationId);
        rootId = jdbc.queryForObject("INSERT INTO users (email, display_name) "
                + "VALUES ('root@certping.test', 'Root') RETURNING id", Integer.class);
        interceptor = new AuditInterceptor(recorder);
        asMember(adminId, organizationId, "ORGANIZATION_ADMIN");
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void pageLoadsLeaveNoRowAndAChangeRequestKeepsItsOne() {
        for (int i = 0; i < 25; i++) {
            request("GET", "/api/v1/agent/health", "/api/v1/agent/health", 200);
        }
        request("HEAD", "/api/v1/certs", "/api/v1/certs", 200);
        request("GET", "/api/v1/certs?search=secret-term", "/api/v1/certs", 200);
        request("POST", "/api/v1/integrations", "/api/v1/integrations", 201);

        await().atMost(Duration.ofSeconds(5)).until(() -> count("SELECT count(*) FROM audit_events") == 1);
        await().during(Duration.ofMillis(400)).atMost(Duration.ofSeconds(3)).until(() -> true);

        assertThat(jdbc.queryForMap("SELECT event, visibility, details::text AS details FROM audit_events"))
                .containsEntry("event", "api.request").containsEntry("visibility", "INTERNAL");
        assertThat(jdbc.queryForList("SELECT audit_events::text FROM audit_events", String.class))
                .allSatisfy(row -> assertThat(row).doesNotContain("secret-term").doesNotContain("bob.admin"));
    }

    @Test
    void aSensitiveReadPolledForFifteenMinutesIsOneAccessRowPerTarget() throws Exception {
        Method connection = Endpoints.class.getMethod("connectionString", Long.class);
        Method cbom = Endpoints.class.getMethod("cbom");
        for (int i = 0; i < 30; i++) {
            reads.record(connection.getAnnotation(AuditedRead.class), connection, new Object[]{null});
            reads.record(cbom.getAnnotation(AuditedRead.class), cbom, new Object[0]);
        }
        // A super admin reading two customers' connection strings: a staff row in each customer's trail.
        asMember(rootId, null, "SUPER_ADMIN");
        for (long target : new long[]{organizationId, otherOrganizationId, organizationId}) {
            reads.record(connection.getAnnotation(AuditedRead.class), connection, new Object[]{target});
        }

        await().atMost(Duration.ofSeconds(5)).until(() -> count("SELECT count(*) FROM audit_events") == 4);
        await().during(Duration.ofMillis(400)).atMost(Duration.ofSeconds(3)).until(() -> true);

        assertThat(jdbc.queryForList("SELECT event || ':' || organization_id || ':' || actor_label || ':' "
                        + "|| actor_staff FROM audit_events WHERE category = 'ACCESS' ORDER BY id", String.class))
                .containsExactlyInAnyOrder(
                        "access.agent_connection_viewed:" + organizationId + ":Bob Admin:false",
                        "access.cbom_downloaded:" + organizationId + ":Bob Admin:false",
                        "access.agent_connection_viewed:" + organizationId + ":Root:true",
                        "access.agent_connection_viewed:" + otherOrganizationId + ":Root:true");
        assertThat(count("SELECT count(*) FROM audit_events WHERE visibility <> 'CUSTOMER'")).isZero();
    }


    /** One request through the interceptor, as the dispatcher runs it. */
    private void request(String method, String uri, String route, int status) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, uri.replaceAll("\\?.*", ""));
        if (uri.contains("?")) {
            request.setQueryString(uri.substring(uri.indexOf('?') + 1));
        }
        request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, route);
        MockHttpServletResponse response = new MockHttpServletResponse();
        interceptor.preHandle(request, response, new Object());
        response.setStatus(status);
        interceptor.afterCompletion(request, response, new Object(), null);
    }

    private void asMember(int userId, Long organization, String role) {
        GatewayRequestContext.set(userId, organization == null ? null : String.valueOf(organization), "req-1",
                null);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", null,
                List.of(new SimpleGrantedAuthority("ROLE_" + role))));
    }

    private int count(String sql) {
        Integer count = jdbc.queryForObject(sql, Integer.class);
        return count == null ? 0 : count;
    }
}
