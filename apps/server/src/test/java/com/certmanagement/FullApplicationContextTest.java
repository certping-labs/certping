// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement;

import com.certmanagement.aspect.FeatureGatedAspect;
import com.certmanagement.audit.AuditAsyncWriter;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.constants.Paths;
import com.certmanagement.messaging.CertResponseProcessor;
import com.certmanagement.security.JwtTestKeys;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.lifecycle.FeatureLifecycleRegistry;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.service.status.PublicStatusBoard;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.AbstractAutowireCapableBeanFactory;
import org.springframework.boot.context.logging.LoggingApplicationListener;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.SmartLifecycle;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.TestPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;

import static com.certmanagement.constants.FeatureFlags.CERTIFICATE_DEPLOYMENT;
import static com.certmanagement.constants.FeatureFlags.CERTIFICATE_RENEWAL;
import static com.certmanagement.constants.FeatureFlags.DISCOVERY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boots the whole application, every bean a pod creates, against real PostgreSQL (Flyway migrates
 * every version) and Redis. Nothing in the application is mocked: a bean cycle, a missing bean or a
 * migration that does not apply fails here instead of on a pod. Each deployment mode has its own
 * bean graph, so each has a subclass with its own containers.
 *
 * <p>Circular references stay disallowed (Spring Boot's default since 2.6): a cycle is a startup
 * failure, never something the container quietly works around.
 */
@SpringBootTest(classes = CertManagementServiceApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "classpath:full-application-context.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
abstract class FullApplicationContextTest {

    private static final String JWT_KEY_ID = "context-test";
    private static final KeyPair JWT_KEYS = JwtTestKeys.rsa(2048);

    @Autowired
    protected ConfigurableApplicationContext context;

    @LocalServerPort
    private int port;

    static PostgreSQLContainer postgres() {
        return new PostgreSQLContainer("postgres:16-alpine");
    }

    static GenericContainer<?> redis() {
        return new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine")).withExposedPorts(6379);
    }

    /** The values a deployment injects per stack: its database, its Redis and its token keys. */
    static void registerStackProperties(DynamicPropertyRegistry registry, PostgreSQLContainer postgres,
                                        GenericContainer<?> redis) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
        registry.add("jwt.signing-key-id", () -> JWT_KEY_ID);
        registry.add("jwt.signing-private-key", () -> JwtTestKeys.privatePem(JWT_KEYS));
        registry.add("jwt.published-keys", () -> JwtTestKeys.jwks(JwtTestKeys.publicJwk(JWT_KEY_ID, JWT_KEYS)));
    }

    @Test
    void circularReferencesStayDisallowed() {
        AbstractAutowireCapableBeanFactory beanFactory =
                (AbstractAutowireCapableBeanFactory) context.getAutowireCapableBeanFactory();

        assertThat(beanFactory.isAllowCircularReferences()).isFalse();
        assertThat(context.getEnvironment().getProperty("spring.main.allow-circular-references", Boolean.class))
                .isNotEqualTo(Boolean.TRUE);
    }

    @Test
    void featureFlagAndLifecycleBeansResolve() {
        assertThat(context.getBean(FeatureFlagService.class)).isNotNull();
        assertThat(context.getBean(FeatureLifecycleService.class)).isNotNull();
        assertThat(context.getBean(ForcedFlagChanges.class)).isNotNull();
        assertThat(context.getBean(FeatureGatedAspect.class)).isNotNull();
        assertThat(context.getBean(CertResponseProcessor.class)).isNotNull();
    }

    /**
     * The audit tables exist and the audit writer runs; it stops after every other lifecycle bean, so whatever the
     * web server, the schedulers and the gRPC server queue while they shut down is still written.
     */
    @Test
    void auditFoundationIsWiredAndItsWriterStopsLast() {
        assertThat(context.getBean(AuditRecorder.class)).isNotNull();
        AuditAsyncWriter writer = context.getBean(AuditAsyncWriter.class);
        assertThat(writer.isRunning()).isTrue();
        // Boot's logging shutdown is meant to stop later still, so the drain can log.
        assertThat(context.getBeansOfType(SmartLifecycle.class).values())
                .filteredOn(lifecycle -> lifecycle != writer)
                .filteredOn(lifecycle -> !lifecycle.getClass().getName().startsWith(LoggingApplicationListener.class.getName()))
                .isNotEmpty()
                .allSatisfy(lifecycle -> assertThat(lifecycle.getPhase()).as(lifecycle.getClass().getName())
                        .isGreaterThan(writer.getPhase()));

        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_inherits WHERE inhparent = 'audit_events'::regclass",
                Integer.class)).isGreaterThanOrEqualTo(17);
    }

    /** The registry holds the platform-pausable lifecycles once the whole context has started. */
    @Test
    void registryHoldsThePlatformPausableLifecycles() {
        FeatureLifecycleRegistry registry = context.getBean(FeatureLifecycleRegistry.class);

        assertThat(registry.findPausable(CERTIFICATE_RENEWAL)).isPresent();
        assertThat(registry.findPausable(DISCOVERY)).isPresent();
    }

    /**
     * A super admin's global switch reaches ForcedFlagChanges through its provider, inside the flag
     * write's transaction: the recorder is {@code MANDATORY} and would refuse to run outside one.
     */
    @Test
    void superAdminGlobalSwitchRecordsForcedTransitions() {
        FeatureFlagService flags = context.getBean(FeatureFlagService.class);
        long recordedBefore = forcedTransitionCount(DISCOVERY);

        flags.updateGlobal(DISCOVERY, false, "full context test");
        flags.updateGlobal(DISCOVERY, true, "full context test");

        assertThat(forcedTransitionCount(DISCOVERY)).isEqualTo(recordedBefore + 2);
    }

    /**
     * An organization admin's switch-off reaches the clear-first guard through its provider, inside
     * the flag write's transaction (the guard is {@code MANDATORY}); nothing is in use, so it saves.
     */
    @Test
    void organizationAdminSwitchOffPassesTheClearFirstGuard() {
        FeatureFlagService flags = context.getBean(FeatureFlagService.class);
        long organizationId = createOrganization();

        flags.upsertOrgOverride(organizationId, CERTIFICATE_DEPLOYMENT, false, "full context test");

        assertThat(flags.isEnabled(CERTIFICATE_DEPLOYMENT, organizationId)).isFalse();
    }

    /** The organization type this deployment mode serves. */
    protected abstract String organizationType();

    /**
     * Over a real socket to the embedded server, so the real filter order and response wrappers apply. The
     * first round completed against the real pool while the context started, before the pod could report
     * ready. A stray token is ignored, CORS applies, the document keeps its cache header while a neighbouring
     * endpoint keeps Spring Security's no-store, and only GET is mapped. The notifier and the agent point at
     * an address nothing listens on, so they report an outage.
     */
    @Test
    void publicStatusIsServedOnTheWireWithItsCacheHeader() throws Exception {
        assertThat(context.getBean(PublicStatusBoard.class).summary()).isPresent();
        HttpClient http = HttpClient.newHttpClient();

        HttpResponse<String> status = http.send(request(Paths.PUBLIC_STATUS)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-token")
                        .header(HttpHeaders.ORIGIN, "http://localhost:3000")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(status.statusCode()).isEqualTo(200);
        assertThat(status.headers().allValues(HttpHeaders.CACHE_CONTROL)).containsExactly("public, max-age=30");
        assertThat(status.headers().firstValue(HttpHeaders.PRAGMA)).isEmpty();
        assertThat(status.headers().firstValue(HttpHeaders.EXPIRES)).isEmpty();
        assertThat(status.headers().firstValue(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)).hasValue("http://localhost:3000");
        JsonNode components = JsonMapper.builderWithJackson2Defaults().build().readTree(status.body()).get("components");
        assertThat(components.findValuesAsString("id")).containsExactly("api", "notifications", "certificates");
        assertThat(components.findValuesAsString("status")).containsExactly("operational", "partial_outage",
                "partial_outage");

        HttpResponse<String> neighbour = http.send(request(Paths.DEPLOYMENT_INFO).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(neighbour.statusCode()).isEqualTo(200);
        assertThat(neighbour.headers().allValues(HttpHeaders.CACHE_CONTROL))
                .containsExactly("no-cache, no-store, max-age=0, must-revalidate");
        assertThat(neighbour.headers().firstValue(HttpHeaders.PRAGMA)).hasValue("no-cache");

        HttpResponse<String> post = http.send(request(Paths.PUBLIC_STATUS)
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(post.statusCode()).isEqualTo(405);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
    }

    private long createOrganization() {
        String slug = "context-test-" + organizationType().toLowerCase();
        return jdbc().queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, ?) RETURNING id", Long.class, slug, slug + ".test", slug, organizationType());
    }

    private long forcedTransitionCount(String featureKey) {
        return jdbc().queryForObject("SELECT COUNT(*) FROM feature_lifecycle_transition WHERE feature_key = ?",
                Long.class, featureKey);
    }

    private JdbcTemplate jdbc() {
        return context.getBean(JdbcTemplate.class);
    }

}
