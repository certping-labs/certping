// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.audit.AuditAsyncWriter;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DeploymentEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.messaging.model.CertDeploymentResponse;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import com.certmanagement.messaging.model.CertRevocationResponse;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.messaging.security.VerifiedAgentMessage;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateCryptoMetadataRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.AlertService;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.agent.AgentHealthService;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.AkamaiSpecialIssuanceService;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.cert.CredentialReferenceService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.DeploymentExecutionService.AutoDeployOutcome;
import com.certmanagement.service.deployment.DeploymentTrackingService;
import com.certmanagement.service.discovery.DiscoveryService;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * What the agent reports, recorded on PostgreSQL 15 through the real recorder, store and async writer, with the
 * response processor's real repositories and transactions. The deployment, revocation and error handlers run
 * with no transaction open: each must still record its row (no IllegalTransactionStateException, the message is
 * completed, not abandoned). Every agent-result row is CertPing's, names the requesting member by id and carries the
 * message's correlation id; a redelivery writes no second row; and nothing an agent's error text holds (hostnames,
 * vault names, SQL, stack frames) is stored or rendered. An automatic deploy that partly succeeds records each target.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms", "certping.audit.async.retry-for=1s"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditEventStore.class, AuditAsyncWriter.class, AuditRecorder.class, CertificateAuditRecorder.class,
        com.certmanagement.service.audit.CredentialAuditRecorder.class,
        JacksonAutoConfiguration.class, CertificateAgentAuditPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class CertificateAgentAuditPostgresTest {

    /** PostgreSQL 15, as the other audit tests use. */
    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:15-alpine");

    /** What an agent's error text may hold; none of it may reach a row or a rendered reason. */
    private static final List<String> LEAKS = List.of("example-vault-prod", "vault.azure.net", "db01.internal",
            "jdbc:postgresql", "SELECT", "pg_catalog", "at com.certping", "NullPointerException", "10.0.4.12",
            "acme-prod-gw.corp.local");
    private static final String RAW_DETAIL = """
            Import failed: https://example-vault-prod.vault.azure.net/certificates/x \
            403 from 10.0.4.12; caused by org.postgresql.util.PSQLException at jdbc:postgresql://db01.internal:5432 \
            SELECT * FROM pg_catalog.pg_tables
            \tat com.certping.agent.Deploy.run(Deploy.java:42) \
            java.lang.NullPointerException acme-prod-gw.corp.local""";

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

    @Autowired private CertificateRepository certificates;
    @Autowired private CertificateEventRepository events;
    @Autowired private RenewalScheduleRepository schedules;
    @Autowired private DomainCredentialConfigRepository credConfigs;
    @Autowired private CertManualIssuanceStateRepository manualStates;
    @Autowired private CertificateCryptoMetadataRepository cryptoMetadata;
    @Autowired private DeploymentRepository deployments;
    @Autowired private CredentialReferenceRepository credentials;
    @Autowired private UserDomainCertRepository udcs;
    @Autowired private CertificateAuditRecorder certificateAudit;
    /** The real store, spied so a test can make the database refuse a row inside the agent's transaction. */
    @MockitoSpyBean private AuditEventStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private TransactionTemplate transactions;

    private final DeploymentExecutionService deployer = mock(DeploymentExecutionService.class);
    private final FeatureLifecycleLock lock = mock(FeatureLifecycleLock.class);
    private final FeatureFlagResolver resolver = mock(FeatureFlagResolver.class);
    private final ObjectMapper json = JsonMapper.builderWithJackson2Defaults().build();
    private CertResponseProcessor processor;
    private long org;
    private long udc;
    private long config;
    private int member;

    @BeforeEach
    void seed() {
        store.createPartition(YearMonth.now(ZoneOffset.UTC));
        store.createPartition(YearMonth.now(ZoneOffset.UTC).plusMonths(1));
        String slug = "acme-" + UUID.randomUUID();
        org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type) VALUES (?, ?, ?, 'B2B')"
                + " RETURNING id", Long.class, slug, slug + ".test", slug);
        member = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) VALUES (?, 'Alice', ?)"
                + " RETURNING id", Integer.class, slug + "@acme.test", org);
        udc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'example.com') RETURNING id", Long.class, org);
        config = jdbc.queryForObject("INSERT INTO domain_credential_config (user_domain_cert_id, deployment_targets)"
                + " VALUES (?, '[]'::jsonb) RETURNING id", Long.class, udc);
        when(resolver.resolveUncached(any(), any())).thenReturn(true);
        when(deployer.planAutoDeploy(any(), anyBoolean())).thenReturn(AutoDeployOutcome.NOTHING_TO_DEPLOY);
        processor = new CertResponseProcessor(certificates, cryptoMetadata, events, schedules, credConfigs,
                manualStates, mock(CertIssuanceService.class), mock(NotificationPublisher.class),
                new AlertService(mock(AlertRepository.class), mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class)), json, deployer,
                mock(CertDeploymentConfigService.class), credentials, mock(AgentHealthService.class),
                mock(AgentDeepHealthCheckService.class), mock(DiscoveryService.class),
                mock(com.certmanagement.iot.messaging.IotIdentitySyncResponseHandler.class),
                mock(com.certmanagement.iot.service.IotDeviceSourceHealthService.class),
                mock(com.certmanagement.iot.profile.CertificateProfileResponseHandler.class),
                mock(com.certmanagement.iot.certificate.IotCertificateIngestionService.class),
                mock(com.certmanagement.iot.certificate.IotDeviceNudgeResultService.class),
                mock(com.certmanagement.iot.cahealth.IotCaHealthService.class),
                mock(com.certmanagement.iot.revocation.IotRevocationResultService.class),
                mock(com.certmanagement.iot.revocation.IotIntuneRevocationWorkflow.class),
                transactions, lock, resolver, deployments, certificateAudit);
    }

    // ── Success responses ───────────────────────────────────────────────

    @Test
    void anIssuanceIsCertPingsRowForTheMemberWhoRequestedIt() throws Exception {
        String xref = certificate("PENDING", false);
        String request = requested(xref, "ISSUANCE_REQUESTED");
        CertIssuanceResponse response = issuance(xref, request, "ISSUED");

        assertThat(deliver("CERT_ISSUANCE_RESPONSE", response)).isTrue();

        Map<String, Object> row = onlyRow("certificate.issued");
        assertThat(row).containsEntry("actor_type", "SYSTEM").containsEntry("actor_label", "CertPing (automatic)")
                .containsEntry("actor_job", "agent-response").containsEntry("outcome", "SUCCESS")
                .containsEntry("correlation_id", "corr-from-message").containsEntry("organization_id", org)
                .containsEntry("resource_ref", xref)
                .containsEntry("summary", "Issued the certificate for example.com from Let's Encrypt");
        assertThat(row.get("actor_user_id")).isNull();
        assertThat(row.get("details").toString()).contains("\"requestedBy\": \"" + member + "\"");
    }

    @Test
    void aRenewalIsRecordedOnceHoweverOftenItIsDelivered() throws Exception {
        String previous = certificate("RENEWING", true);
        String renewed = draft();
        CertIssuanceResponse response = issuance(renewed, "req-renew-" + UUID.randomUUID(), "RENEWED");

        assertThat(deliver("CERT_ISSUANCE_RESPONSE", response)).isTrue();
        assertThat(deliver("CERT_ISSUANCE_RESPONSE", response)).isTrue();

        Map<String, Object> row = onlyRow("certificate.renewed");
        assertThat(row).containsEntry("resource_ref", renewed).containsEntry("actor_type", "SYSTEM");
        assertThat(row.get("details").toString()).contains("\"replaces\": \"" + previous + "\"")
                .doesNotContain("requestedBy");
    }

    @Test
    void aDeploymentResponse_withNoTransactionOpen_recordsItsRowInOneOfItsOwn() throws Exception {
        String xref = certificate("ACTIVE", true);
        String request = requested(xref, "DEPLOYMENT_REQUESTED");
        CertDeploymentResponse response = deployment(xref, request, "https://kv-acme.vault.azure.net/certificates/x");

        assertThat(deliver("CERT_DEPLOYMENT_RESPONSE", response)).as("completed, not abandoned").isTrue();
        assertThat(deliver("CERT_DEPLOYMENT_RESPONSE", response)).isTrue();

        Map<String, Object> row = onlyRow("deployment.succeeded");
        assertThat(row).containsEntry("summary", "Deployed the certificate for example.com to Azure Key Vault")
                .containsEntry("resource_type", "DEPLOYMENT").containsEntry("category", "DEPLOYMENTS");
        assertThat(row.get("details").toString()).contains("\"requestedBy\": \"" + member + "\"")
                .doesNotContain("kv-acme");
    }

    @Test
    void aMalformedDeploymentResponseIsAFailureOfOurs() throws Exception {
        String xref = certificate("ACTIVE", true);
        CertDeploymentResponse response = deployment(xref, "req-" + UUID.randomUUID(), "example-vault-prod/not-a-uri");

        assertThat(deliver("CERT_DEPLOYMENT_RESPONSE", response)).isTrue();

        Map<String, Object> row = onlyRow("deployment.failed");
        assertThat(row).containsEntry("outcome", "FAILURE").containsEntry("error_code", "INTERNAL_ERROR");
        assertNoLeak();
    }

    @Test
    void aRevocation_withNoTransactionOpen_isRecordedWithTheStatusChange() throws Exception {
        String xref = certificate("REVOKING", true);
        String request = requested(xref, "REVOCATION_REQUESTED");
        CertRevocationResponse response = new CertRevocationResponse();
        response.setRequestId(request);
        response.setCorrelationId("corr-from-message");
        response.setOrganizationId(String.valueOf(org));
        response.setCertificateXref(xref);
        response.setCaProvider(CaProvider.LETS_ENCRYPT);
        response.setRevocationReason("KEY_COMPROMISE");

        assertThat(deliver("CERT_REVOCATION_RESPONSE", response)).isTrue();

        assertThat(jdbc.queryForObject("SELECT status FROM certificates WHERE certificate_xref = ?", String.class, xref))
                .isEqualTo("REVOKED");
        Map<String, Object> row = onlyRow("certificate.revoked");
        assertThat(row).containsEntry("summary", "Revoked the certificate for example.com");
        assertThat(row.get("details").toString()).contains("\"revocationReason\": \"KEY_COMPROMISE\"")
                .contains("\"requestedBy\": \"" + member + "\"");
    }

    // ── The trail never blocks the certificate's state ──────────────────

    @Test
    void aRowTheDatabaseRefuses_neverRollsBackTheAgentsResult_andIsWrittenByTheAsyncWriter() throws Exception {
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        Metrics.addRegistry(metrics);
        Thread processing = Thread.currentThread();
        Set<String> refused = Set.of("certificate.issued", "deployment.succeeded", "certificate.revoked");
        // The database refuses the row on the agent's own transaction (a failed statement aborts a PostgreSQL
        // transaction): only the savepoint keeps the certificate's state committable.
        doAnswer(call -> {
            AuditEventRow row = call.getArgument(0);
            if (Thread.currentThread() == processing && refused.contains(row.event())) {
                jdbc.queryForObject("SELECT 1 / 0", Integer.class);
            }
            return call.callRealMethod();
        }).when(store).insert(any());
        try {
            // Created first: the issuance makes its certificate the domain's active one.
            String deploying = certificate("ACTIVE", true);
            String revoking = certificate("REVOKING", true);
            String issuing = certificate("PENDING", false);
            assertThat(deliver("CERT_ISSUANCE_RESPONSE", issuance(issuing, requested(issuing, "ISSUANCE_REQUESTED"),
                    "ISSUED"))).as("acknowledged").isTrue();
            assertThat(deliver("CERT_DEPLOYMENT_RESPONSE", deployment(deploying, requested(deploying,
                    "DEPLOYMENT_REQUESTED"), "https://kv-acme.vault.azure.net/certificates/x"))).isTrue();
            CertRevocationResponse revocation = new CertRevocationResponse();
            revocation.setRequestId(requested(revoking, "REVOCATION_REQUESTED"));
            revocation.setOrganizationId(String.valueOf(org));
            revocation.setCertificateXref(revoking);
            assertThat(deliver("CERT_REVOCATION_RESPONSE", revocation)).isTrue();

            assertThat(status(issuing)).isEqualTo("ACTIVE");
            assertThat(status(revoking)).isEqualTo("REVOKED");
            assertThat(timeline(issuing, "ISSUANCE_SUCCESS")).isOne();
            assertThat(timeline(deploying, "DEPLOYMENT_SUCCESS")).isOne();
            assertThat(timeline(revoking, "REVOCATION_SUCCESS")).isOne();
            assertThat(refused).allSatisfy(event -> assertThat(metrics.get("certping.audit.isolated.fallback")
                    .tag("event", event).counter().count()).as(event).isEqualTo(1.0));
            await().atMost(Duration.ofSeconds(5)).until(() -> rows() == 3);
            assertThat(jdbc.queryForList("SELECT event FROM audit_events WHERE organization_id = ? ORDER BY event",
                    String.class, org)).containsExactly("certificate.issued", "certificate.revoked",
                    "deployment.succeeded");
        } finally {
            Metrics.removeRegistry(metrics);
        }
    }

    @Test
    void aRowThatFailsBeforeAnySqlRuns_fallsBackTheSameWay() throws Exception {
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        Metrics.addRegistry(metrics);
        Thread processing = Thread.currentThread();
        doAnswer(call -> {
            AuditEventRow row = call.getArgument(0);
            if (Thread.currentThread() == processing && "certificate.issued".equals(row.event())) {
                throw new IllegalStateException("details could not be serialised");
            }
            return call.callRealMethod();
        }).when(store).insert(any());
        try {
            String issuing = certificate("PENDING", false);
            assertThat(deliver("CERT_ISSUANCE_RESPONSE", issuance(issuing, requested(issuing, "ISSUANCE_REQUESTED"),
                    "ISSUED"))).as("acknowledged").isTrue();

            assertThat(status(issuing)).isEqualTo("ACTIVE");
            assertThat(timeline(issuing, "ISSUANCE_SUCCESS")).isOne();
            assertThat(metrics.get("certping.audit.isolated.fallback").tag("event", "certificate.issued").counter()
                    .count()).isEqualTo(1.0);
            await().atMost(Duration.ofSeconds(5)).until(() -> rows() == 1);
        } finally {
            Metrics.removeRegistry(metrics);
        }
    }

    // ── Agent errors (no transaction open) ──────────────────────────────

    @Test
    void everyAgentFailureIsRecordedWithItsReason() throws Exception {
        String issuing = certificate("PENDING", false);
        String renewing = certificate("PENDING", false);
        String deploying = certificate("ACTIVE", true);
        String revoking = certificate("REVOKING", true);
        String deployRequest = requested(deploying, "DEPLOYMENT_REQUESTED");
        when(deployer.findDeployment(eq(deployRequest), eq(org))).thenReturn(Optional.of(DeploymentEntity.builder()
                .requestId(deployRequest).targetType("GCP_CERT_MANAGER").flowType("MANUAL").build()));

        assertThat(deliver("AGENT_ERROR", error("CERT_ISSUANCE", issuing, requested(issuing, "ISSUANCE_REQUESTED"),
                "RETRY_GIVE_UP", "DNS_AUTH_FAILED"))).isTrue();
        assertThat(deliver("AGENT_ERROR", error("CERT_RENEWAL", renewing, "req-" + UUID.randomUUID(),
                "ACME_RATE_LIMITED", null))).isTrue();
        assertThat(deliver("AGENT_ERROR", error("CERT_DEPLOYMENT", deploying, deployRequest,
                "RETRY_GIVE_UP", "DEPLOY_GCP_SSL_CERT_FAILED"))).isTrue();
        assertThat(deliver("AGENT_ERROR", error("CERT_REVOCATION_COMMAND", revoking,
                requested(revoking, "REVOCATION_REQUESTED"), "REVOCATION_UNAUTHORIZED", null))).isTrue();

        List<Map<String, Object>> rows = jdbc.queryForList("SELECT event, outcome, error_code, summary, actor_type "
                + "FROM audit_events WHERE organization_id = ? ORDER BY id", org);
        assertThat(rows).extracting(r -> r.get("event")).containsExactly("certificate.issued", "certificate.renewed",
                "deployment.failed", "certificate.revoked");
        assertThat(rows).extracting(r -> r.get("error_code")).containsExactly("DNS_AUTH_FAILED", "ACME_RATE_LIMITED",
                "DEPLOY_GCP_SSL_CERT_FAILED", "REVOCATION_UNAUTHORIZED");
        assertThat(rows).extracting(r -> r.get("summary")).containsExactly(
                "Issuing the certificate for example.com failed",
                "Renewing the certificate for example.com failed",
                "Deploying the certificate for example.com to Google Cloud Certificate Manager failed",
                "Revoking the certificate for example.com failed");
        assertThat(rows).allSatisfy(r -> assertThat(r).containsEntry("outcome", "FAILURE")
                .containsEntry("actor_type", "SYSTEM"));
        assertNoLeak();
    }

    @Test
    void anAgentErrorsTextIsNeverStoredOrRendered() throws Exception {
        String deploying = certificate("ACTIVE", true);
        String issuing = certificate("PENDING", false);
        String renewing = certificate("PENDING", false);

        deliver("AGENT_ERROR", error("CERT_DEPLOYMENT", deploying, "req-" + UUID.randomUUID(),
                "DEPLOY_AZURE_KV_IMPORT_FAILED", "example-vault-prod.vault.azure.net"));
        deliver("AGENT_ERROR", error("CERT_ISSUANCE", issuing, "req-" + UUID.randomUUID(), "RETRY_GIVE_UP",
                "SELECT * FROM pg_catalog.pg_tables at jdbc:postgresql://db01.internal"));
        deliver("AGENT_ERROR", error("CERT_RENEWAL", renewing, "req-" + UUID.randomUUID(),
                "jdbc:postgresql://db01.internal:5432/certping", "at com.certping.agent.Run(Run.java:1)"));

        List<String> codes = jdbc.queryForList("SELECT error_code FROM audit_events WHERE organization_id = ? "
                + "ORDER BY id", String.class, org);
        assertThat(codes).containsExactly("DEPLOY_AZURE_KV_IMPORT_FAILED", "INTERNAL_ERROR", "INTERNAL_ERROR");
        assertNoLeak();
        assertThat(codes).allSatisfy(code -> assertThat(AuditReason.of(code).message("req-1"))
                .satisfies(message -> LEAKS.forEach(leak -> assertThat(message).doesNotContain(leak))));
    }

    // ── An automatic deploy that partly succeeds ────────────────────────

    @Test
    void anAutomaticDeploy_recordsEveryTarget_aFailedOneWithItsReason() {
        String xref = certificate("ACTIVE", true);
        CertificateEntity cert = certificates.findByCertificateXref(xref).orElseThrow();
        CredentialReferenceService credentialService = mock(CredentialReferenceService.class);
        CertAgentPublisher publisher = mock(CertAgentPublisher.class);
        when(credentialService.getByXref(org, "cred-ok")).thenReturn(credential("cred-ok", "AZURE_KV", "ACTIVE"));
        when(credentialService.getByXref(org, "cred-down")).thenReturn(credential("cred-down", "AWS_ACM", "ACTIVE"));
        when(credentialService.getByXref(org, "cred-off")).thenReturn(credential("cred-off", "AZURE_KV", "DELETED"));
        when(credentialService.getByXref(org, "cred-gone")).thenThrow(new ResourceNotFoundException("gone"));
        doThrow(new IllegalStateException("queue down at db-certping-prod.internal.example")).when(publisher)
                .publishDeployment(argThat(command -> command != null
                        && command.getTargetType() == TargetType.AWS_ACM));
        CertDeploymentConfigService configs = mock(CertDeploymentConfigService.class);
        when(configs.findReconciledConfigJson(anyLong(), anyLong(), any())).thenReturn(Optional.empty());
        DeploymentExecutionService real = new DeploymentExecutionService(credentialService, publisher,
                mock(DeploymentTrackingService.class), udcs, schedules, credConfigs, configs, certificates,
                mock(AkamaiSpecialIssuanceService.class), json, mock(OrgTypeResolver.class),
                mock(FeatureFlagService.class), certificateAudit);

        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.AGENT_JOB, org, "corr-from-message")) {
            real.dispatchAll(org, cert, "https://kv.example/secrets/cert", List.of("cred-ok", "cred-down", "cred-off",
                    "cred-gone"), "AUTO_POST_ISSUANCE");
        }

        await().atMost(Duration.ofSeconds(5)).until(() -> rows() == 4);
        List<Map<String, Object>> rows = jdbc.queryForList("SELECT event, outcome, error_code, summary FROM "
                + "audit_events WHERE organization_id = ? ORDER BY summary", org);
        assertThat(rows).extracting(r -> r.get("event") + "|" + r.get("error_code")).containsExactlyInAnyOrder(
                "deployment.auto_started|null",
                "deployment.failed|SERVICE_UNAVAILABLE",
                "deployment.failed|DEPLOYMENT_CREDENTIAL_INVALID",
                "deployment.failed|DEPLOYMENT_CREDENTIAL_MISSING");
        assertThat(rows).extracting(r -> (String) r.get("summary")).contains(
                "Started deploying the certificate for example.com to Azure Key Vault automatically",
                "Deploying the certificate for example.com to AWS Certificate Manager failed",
                "Deploying the certificate for example.com failed");
        assertThat(jdbc.queryForList("SELECT audit_events::text FROM audit_events WHERE organization_id = ?",
                String.class, org)).allSatisfy(text -> assertThat(text).doesNotContain("db-certping-prod"));
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private boolean deliver(String messageType, Object message) throws Exception {
        AtomicBoolean completed = new AtomicBoolean();
        AtomicBoolean abandoned = new AtomicBoolean();
        processor.process(messageType, json.writeValueAsString(message),
                VerifiedAgentMessage.unverified(String.valueOf(org), messageType, "msg-" + UUID.randomUUID(),
                        OffsetDateTime.now()),
                () -> completed.set(true), () -> abandoned.set(true));
        assertThat(abandoned).as("%s abandoned (an IllegalTransactionStateException or a write failure)", messageType)
                .isFalse();
        return completed.get();
    }

    /** A certificate of this organization in {@code status}; issued already (valid, with a secret handle) or not. */
    private String certificate(String status, boolean issued) {
        String xref = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status, valid_to,"
                        + " cert_secret_handle) VALUES (?, ?, 'LETS_ENCRYPT', ?, ?, ?)", xref, udc, status,
                issued ? OffsetDateTime.now().plusDays(60) : null, issued ? "https://kv.example/secrets/" + xref : null);
        jdbc.update("INSERT INTO renewal_schedule (certificate_xref, domain_credential_config_id, valid_to,"
                + " renewal_eligible_at, ca_provider, enabled) VALUES (?, ?, NOW(), NOW(), 'LETS_ENCRYPT', FALSE)",
                xref, config);
        return xref;
    }

    /** A renewal's draft: PENDING, with no schedule of its own (the schedule moves to it once renewed). */
    private String draft() {
        String xref = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', 'PENDING')", xref, udc);
        return xref;
    }

    /** The member's request event for {@code xref}: what an agent response's requestedBy is read from. */
    private String requested(String xref, String eventType) {
        String request = "req-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificate_events (certificate_xref, organization_id, event_type, request_id,"
                + " user_id, source) VALUES (?, ?, ?, ?, ?, 'certping-cert-manager')", xref, org, eventType, request,
                member);
        return request;
    }

    private CertIssuanceResponse issuance(String xref, String request, String status) {
        CertIssuanceResponse response = new CertIssuanceResponse();
        response.setRequestId(request);
        response.setCorrelationId("corr-from-message");
        response.setOrganizationId(String.valueOf(org));
        response.setCertificateXref(xref);
        response.setStatus(status);
        response.setCaProvider(CaProvider.LETS_ENCRYPT);
        response.setCertSecretHandle("https://kv.example/secrets/" + xref);
        response.setIssuer("Let's Encrypt");
        response.setSerialNumber("04:" + UUID.randomUUID().toString().substring(0, 8));
        response.setValidFrom(OffsetDateTime.now().toString());
        response.setValidTo(OffsetDateTime.now().plusDays(90).toString());
        return response;
    }

    private CertDeploymentResponse deployment(String xref, String request, String targetResourceId) {
        CertDeploymentResponse response = new CertDeploymentResponse();
        response.setRequestId(request);
        response.setCorrelationId("corr-from-message");
        response.setOrganizationId(String.valueOf(org));
        response.setCertificateXref(xref);
        response.setStatus("SUCCESS");
        response.setTargetType(TargetType.AZURE_KV);
        response.setTargetResourceId(targetResourceId);
        return response;
    }

    private AgentErrorMessage error(String originalType, String xref, String request, String code, String lastReason) {
        AgentErrorMessage error = new AgentErrorMessage();
        error.setOriginalMessageType(originalType);
        error.setCertificateXref(xref);
        error.setRequestId(request);
        error.setCorrelationId("corr-from-message");
        error.setOrganizationId(String.valueOf(org));
        error.setErrorCode(code);
        error.setLastReason(lastReason);
        error.setErrorDetail(RAW_DETAIL);
        return error;
    }

    private static CredentialReferenceEntity credential(String xref, String provider, String status) {
        return CredentialReferenceEntity.builder().id((long) xref.hashCode()).credentialXref(xref).provider(provider)
                .type("DEPLOYMENT").status(status).secretHandle("https://kv.example/secrets/" + xref).build();
    }

    private String status(String xref) {
        return jdbc.queryForObject("SELECT status FROM certificates WHERE certificate_xref = ?", String.class, xref);
    }

    private Integer timeline(String xref, String eventType) {
        return jdbc.queryForObject("SELECT count(*) FROM certificate_events WHERE certificate_xref = ? "
                + "AND event_type = ?", Integer.class, xref, eventType);
    }

    private Map<String, Object> onlyRow(String event) {
        List<Map<String, Object>> rows = jdbc.queryForList("SELECT event, visibility, actor_type, actor_label,"
                + " actor_job, actor_user_id, outcome, error_code, correlation_id, organization_id, resource_ref,"
                + " resource_type, category, summary, details::text AS details FROM audit_events"
                + " WHERE organization_id = ?", org);
        assertThat(rows).as("one row for the organization").hasSize(1);
        assertThat(rows.get(0)).containsEntry("event", event).containsEntry("visibility", "CUSTOMER");
        return rows.get(0);
    }

    private int rows() {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE organization_id = ?",
                Integer.class, org);
        return count == null ? 0 : count;
    }

    private void assertNoLeak() {
        assertThat(jdbc.queryForList("SELECT audit_events::text FROM audit_events WHERE organization_id = ?",
                String.class, org)).isNotEmpty().allSatisfy(text -> LEAKS.forEach(leak ->
                assertThat(text).as("stored row").doesNotContain(leak)));
    }
}
