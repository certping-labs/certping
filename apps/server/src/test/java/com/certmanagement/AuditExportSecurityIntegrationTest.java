// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A regression: every audit export answered 200 with all its rows, then the stream was reset (curl 92, the browser's
 * ERR_HTTP2_PROTOCOL_ERROR). Spring Security 6 authorizes the ASYNC re-dispatch a {@code StreamingResponseBody}
 * makes once its body is written, and the JWT filter does not run on it, so the dispatch was anonymous and denied
 * on a committed response. The mocked-out export tests never ran that dispatch through the security chain.
 *
 * <p>Here the whole application boots (real filter chain, real JWT, PostgreSQL, Redis) and each export runs to the
 * end, including the async dispatch: 200, every row, nothing after it.
 */
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = CertManagementServiceApplication.class)
@TestPropertySource(locations = "classpath:full-application-context.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AuditExportSecurityIntegrationTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = FullApplicationContextTest.postgres();

    @Container
    private static final GenericContainer<?> REDIS = FullApplicationContextTest.redis();

    @DynamicPropertySource
    static void stackProperties(DynamicPropertyRegistry registry) {
        FullApplicationContextTest.registerStackProperties(registry, POSTGRES, REDIS);
    }

    @Autowired private WebApplicationContext context;
    @Autowired private JwtTokenProvider tokens;
    @Autowired private JdbcTemplate jdbc;

    private MockMvc mvc;
    private long organizationId;
    private String memberToken;
    private String superAdminToken;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        String slug = "export-" + System.nanoTime();
        organizationId = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type, active, "
                + "is_deleted) VALUES (?, ?, ?, 'B2B', true, false) RETURNING id", Long.class,
                slug, slug + ".test", slug);
        int member = user("alice-" + slug + "@acme.test", organizationId);
        int staff = user("sam-" + slug + "@certping.test", null);
        for (int i = 0; i < 3; i++) {
            jdbc.update("INSERT INTO audit_events (occurred_at, visibility, event, category, organization_id, "
                            + "actor_type, actor_user_id, actor_label, action, resource_type, outcome, summary, "
                            + "request_id) VALUES (?, 'CUSTOMER', ?, ?, ?, 'USER', ?, 'Alice Admin', ?, ?, 'SUCCESS', "
                            + "?, ?)",
                    Timestamp.from(Instant.now().minusSeconds(60 + i)),
                    i == 2 ? "access.audit_log_viewed" : "organization.updated", i == 2 ? "ACCESS" : "ORGANIZATION",
                    organizationId, member, i == 2 ? "VIEW" : "UPDATE", i == 2 ? "AUDIT" : "ORGANIZATION",
                    i == 2 ? "Viewed the audit log" : "Changed the organization's settings", "req-" + i);
        }
        Organization organization = Organization.builder().id(organizationId).name(slug).orgType("B2B").build();
        memberToken = tokens.generateAccessToken(account(member, "ORGANIZATION_ADMIN"), organization, "LOCAL");
        superAdminToken = tokens.generateAccessToken(account(staff, "SUPER_ADMIN"), null, "LOCAL");
    }

    @Test
    void aCustomerExportRunsToTheEndThroughTheSecurityChain() throws Exception {
        String csv = download("/api/v1/audit-logs/export?format=csv", memberToken, "2");
        assertThat(csv.lines().toList()).hasSize(3);
        assertThat(csv).contains("Changed the organization's settings").doesNotContain("Viewed the audit log");

        // The CSV export's own audit_log.exported row is now in the trail, so the JSON export has one more.
        String json = download("/api/v1/audit-logs/export?format=json", memberToken, "3");
        assertThat(json.strip()).startsWith("[").endsWith("]").contains("Exported 2 audit log entries as CSV");
    }

    @Test
    void anAccessExportRunsToTheEndThroughTheSecurityChain() throws Exception {
        String body = download("/api/v1/audit-logs/access/export", memberToken, "1");

        assertThat(body.lines().toList()).hasSize(2);
        assertThat(body).contains("access.audit_log_viewed");
    }

    @Test
    void aPlatformExportRunsToTheEndThroughTheSecurityChain() throws Exception {
        String body = download("/api/v1/admin/audit-logs/export?organizationId=" + organizationId,
                superAdminToken, "3");

        assertThat(body.lines().toList()).hasSize(4);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE organization_id = ? "
                + "AND event = 'support.audit_log_exported' AND actor_staff", Long.class, organizationId)).isEqualTo(1);
    }

    @Test
    void anExportWithoutATokenIsStillRefusedOnItsOwnDispatch() throws Exception {
        mvc.perform(get("/api/v1/audit-logs/export")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/admin/audit-logs/export").header(HttpHeaders.AUTHORIZATION, "Bearer " + memberToken))
                .andExpect(status().isForbidden());
    }

    /** The whole exchange: the request dispatch through the chain, then the async dispatch through it too. */
    private String download(String uri, String token, String rows) throws Exception {
        MvcResult started = mvc.perform(get(uri).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(request().asyncStarted())
                .andReturn();
        MvcResult done = mvc.perform(asyncDispatch(started))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Audit-Export-Rows", rows))
                .andReturn();
        assertThat(done.getResolvedException()).isNull();
        return done.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private int user(String email, Long organization) {
        return jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id, active, is_deleted) "
                + "VALUES (?, ?, ?, true, false) RETURNING id", Integer.class, email, email, organization);
    }

    private static User account(int id, String role) {
        Permission auditView = Permission.builder().name("audit:view").build();
        return User.builder().id(id).email("user-" + id + "@example.test")
                .roles(Set.of(Role.builder().name(role).permissions(Set.of(auditView)).build()))
                .build();
    }
}
