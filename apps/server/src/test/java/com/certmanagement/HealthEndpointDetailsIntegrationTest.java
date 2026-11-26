// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement;

import com.certmanagement.entity.Organization;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code /actuator/health} is public on the API host and any customer token used to count as authorized for
 * {@code show-details: when-authorized}, which handed the database, disk and Redis details to every signed-in user.
 * The whole application boots here (real filter chain, real JWT, PostgreSQL, Redis) so the actual configuration answers.
 */
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = CertManagementServiceApplication.class)
@TestPropertySource(locations = "classpath:full-application-context.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class HealthEndpointDetailsIntegrationTest {

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
    private String customerToken;
    private String superAdminToken;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        String slug = "health-" + System.nanoTime();
        long organizationId = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type, active, "
                + "is_deleted) VALUES (?, ?, ?, 'B2B', true, false) RETURNING id", Long.class,
                slug, slug + ".test", slug);
        int customer = user("owner-" + slug + "@acme.test", organizationId);
        int staff = user("staff-" + slug + "@certping.test", null);
        Organization organization = Organization.builder().id(organizationId).name(slug).orgType("B2B").build();
        customerToken = tokens.generateAccessToken(account(customer, "ORGANIZATION_ADMIN"), organization, "LOCAL");
        superAdminToken = tokens.generateAccessToken(account(staff, "SUPER_ADMIN"), null, "LOCAL");
    }

    @Test
    void anonymousCallersSeeOnlyTheStatus() throws Exception {
        assertStatusOnly(get("/actuator/health"));
    }

    @Test
    void signedInCustomersSeeOnlyTheStatus() throws Exception {
        assertStatusOnly(get("/actuator/health").header(HttpHeaders.AUTHORIZATION, "Bearer " + customerToken));
    }

    @Test
    void staffTokensSeeOnlyTheStatus() throws Exception {
        assertStatusOnly(get("/actuator/health").header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminToken));
    }

    @Test
    void theProbeGroupsStillAnswerWithoutAToken() throws Exception {
        assertStatusOnly(get("/actuator/health/liveness"));
        assertStatusOnly(get("/actuator/health/readiness"));
    }

    private void assertStatusOnly(MockHttpServletRequestBuilder request) throws Exception {
        String body = mvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components").doesNotExist())
                .andExpect(jsonPath("$.details").doesNotExist())
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("db").doesNotContain("redis").doesNotContain("diskSpace");
    }

    private int user(String email, Long organization) {
        return jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id, active, is_deleted) "
                + "VALUES (?, ?, ?, true, false) RETURNING id", Integer.class, email, email, organization);
    }

    private static User account(int id, String role) {
        return User.builder().id(id).email("user-" + id + "@example.test")
                .roles(Set.of(Role.builder().name(role).permissions(Set.of()).build()))
                .build();
    }
}
