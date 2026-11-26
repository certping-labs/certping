// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.model.CertIssuanceResponse;
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
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.service.AlertService;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.agent.AgentHealthService;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.DeploymentExecutionService.AutoDeployOutcome;
import com.certmanagement.service.discovery.DiscoveryService;
import com.certmanagement.service.lifecycle.AutoRenewLifecycle;
import com.certmanagement.service.lifecycle.BlockerKind;
import com.certmanagement.service.lifecycle.ClearAction;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.OffsetDateTime;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An issuance success on real PostgreSQL, through its real repositories, advisory locks and flag
 * resolver: it is one transaction (a failure after the certificate update rolls everything back),
 * and it serializes with an org admin's DISABLE_AUTO_RENEW plus switch-off in either order, without
 * deadlock, ending with automatic renewal off.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({FeatureLifecycleLock.class, FeatureFlagResolver.class, CertificateLifecycleRepository.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class CertSuccessPostgresTest {

    private static final String RENEWAL = "CERTIFICATE_RENEWAL";

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

    @Autowired private CertificateRepository certificates;
    @Autowired private CertificateEventRepository events;
    @Autowired private RenewalScheduleRepository schedules;
    @Autowired private DomainCredentialConfigRepository credConfigs;
    @Autowired private CertManualIssuanceStateRepository manualStates;
    @Autowired private CertificateCryptoMetadataRepository cryptoMetadata;
    @Autowired private DeploymentRepository deployments;
    @Autowired private CredentialReferenceRepository credentials;
    @Autowired private FeatureLifecycleLock lock;
    @Autowired private FeatureFlagResolver resolver;
    @Autowired private CertificateLifecycleRepository certificateLifecycle;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private TransactionTemplate transactions;

    private final DeploymentExecutionService deployer = mock(DeploymentExecutionService.class);
    private CertResponseProcessor processor;
    private long org;
    private String xref;

    @BeforeEach
    void seed() {
        // A fresh organization per test: truncating organizations would cascade into the seeded flags.
        String slug = "acme-" + java.util.UUID.randomUUID();
        xref = "cert-" + slug;
        org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, 'B2B') RETURNING id", Long.class, slug, slug + ".test", slug);
        long udc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'example.com') RETURNING id", Long.class, org);
        long config = jdbc.queryForObject("INSERT INTO domain_credential_config (user_domain_cert_id,"
                + " deployment_targets) VALUES (?, '[]'::jsonb) RETURNING id", Long.class, udc);
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', 'PENDING')", xref, udc);
        jdbc.update("INSERT INTO renewal_schedule (certificate_xref, domain_credential_config_id, valid_to,"
                + " renewal_eligible_at, ca_provider, enabled) VALUES (?, ?, NOW(), NOW(), 'LETS_ENCRYPT', FALSE)",
                xref, config);
        when(deployer.planAutoDeploy(any(), anyBoolean())).thenReturn(AutoDeployOutcome.NOTHING_TO_DEPLOY);
        processor = new CertResponseProcessor(certificates, cryptoMetadata, events, schedules, credConfigs,
                manualStates, mock(CertIssuanceService.class), mock(NotificationPublisher.class),
                new AlertService(mock(AlertRepository.class), mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class)), JsonMapper.builderWithJackson2Defaults().build(), deployer,
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
                transactions, lock, resolver, deployments, mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
    }

    @Test
    void aFailureAfterTheCertificateUpdateRollsBackTheScheduleAndEventsToo() throws Exception {
        when(deployer.planAutoDeploy(any(), anyBoolean())).thenThrow(new IllegalStateException("injected"));

        assertThat(deliver()).as("abandoned for redelivery").isFalse();

        assertThat(jdbc.queryForObject("SELECT status FROM certificates WHERE certificate_xref = ?", String.class, xref))
                .isEqualTo("PENDING");
        assertThat(scheduleEnabled()).isFalse();
        assertThat(eventCount("ISSUANCE_SUCCESS")).isZero();
    }

    @Test
    void anAdminsDisableAutoRenewAndSwitchOffFirst_theSuccessWaitsThenLeavesRenewalOff() throws Exception {
        ExecutorService threads = Executors.newFixedThreadPool(2);
        CountDownLatch adminHoldsLock = new CountDownLatch(1);
        CountDownLatch releaseAdmin = new CountDownLatch(1);
        try {
            Future<?> admin = threads.submit(() -> transactions.executeWithoutResult(status -> {
                disableAutoRenewAndSwitchOff();
                adminHoldsLock.countDown();
                await(releaseAdmin);
            }));
            assertThat(adminHoldsLock.await(10, TimeUnit.SECONDS)).isTrue();
            Future<Boolean> success = threads.submit(this::deliver);
            Thread.sleep(500);
            assertThat(success.isDone()).as("the success waits for the admin's locks").isFalse();

            releaseAdmin.countDown();
            admin.get(10, TimeUnit.SECONDS);
            assertThat(success.get(10, TimeUnit.SECONDS)).isTrue();
        } finally {
            releaseAdmin.countDown();
            threads.shutdownNow();
        }

        assertThat(jdbc.queryForObject("SELECT status FROM certificates WHERE certificate_xref = ?", String.class, xref))
                .isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT last_renewal_status FROM renewal_schedule WHERE certificate_xref = ?",
                String.class, xref)).as("renewal was off when the success re-checked it: held")
                .isEqualTo("FEATURE_HOLD");
        assertThat(jdbc.queryForObject("SELECT next_attempt_at IS NOT NULL FROM renewal_schedule"
                + " WHERE certificate_xref = ?", Boolean.class, xref)).as("checked again later").isTrue();
        assertThat(eventCount("AUTO_RENEW_SKIPPED_FEATURE_OFF")).isOne();
    }

    @Test
    void theSuccessFirst_theAdminWaitsThenItsDisableAutoRenewWins() throws Exception {
        ExecutorService threads = Executors.newFixedThreadPool(2);
        CountDownLatch successHoldsLocks = new CountDownLatch(1);
        CountDownLatch releaseSuccess = new CountDownLatch(1);
        doAnswer(call -> {
            successHoldsLocks.countDown();
            await(releaseSuccess);
            return AutoDeployOutcome.NOTHING_TO_DEPLOY;
        }).when(deployer).planAutoDeploy(any(), anyBoolean());
        try {
            Future<Boolean> success = threads.submit(this::deliver);
            assertThat(successHoldsLocks.await(10, TimeUnit.SECONDS)).isTrue();
            Future<?> admin = threads.submit(() -> transactions.executeWithoutResult(
                    status -> disableAutoRenewAndSwitchOff()));
            Thread.sleep(500);
            assertThat(admin.isDone()).as("the admin waits for the success's locks").isFalse();

            releaseSuccess.countDown();
            assertThat(success.get(10, TimeUnit.SECONDS)).isTrue();
            admin.get(10, TimeUnit.SECONDS);
        } finally {
            releaseSuccess.countDown();
            threads.shutdownNow();
        }

        assertThat(eventCount("ISSUANCE_SUCCESS")).isOne();
        assertThat(scheduleEnabled()).as("the clear ran after the success enabled it").isFalse();
        assertThat(resolver.resolveUncached(RENEWAL, org)).isFalse();
    }

    /** What FeatureLifecycleService.clear and the org admin's switch-off do, under the same lock. */
    private void disableAutoRenewAndSwitchOff() {
        lock.lock(org, RENEWAL);
        new AutoRenewLifecycle(RENEWAL, BlockerKind.AUTO_RENEW_CERTS, "Automatic renewals",
                com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewScope.everyCa(),
                certificateLifecycle)
                .clear(org, BlockerKind.AUTO_RENEW_CERTS, ClearAction.DISABLE_AUTO_RENEW);
        jdbc.update("INSERT INTO organization_feature_flags (organization_id, feature_key, enabled, admin_locked)"
                + " VALUES (?, ?, FALSE, FALSE)", org, RENEWAL);
    }

    private boolean deliver() throws Exception {
        CertIssuanceResponse response = new CertIssuanceResponse();
        response.setRequestId("req-" + xref);
        response.setOrganizationId(String.valueOf(org));
        response.setCertificateXref(xref);
        response.setStatus("ISSUED");
        response.setCaProvider(com.certmanagement.enums.CaProvider.LETS_ENCRYPT);
        response.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");
        response.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme");
        response.setSerialNumber("04:AB:CD");
        response.setValidFrom(OffsetDateTime.now().toString());
        response.setValidTo(OffsetDateTime.now().plusDays(90).toString());
        AtomicBoolean completed = new AtomicBoolean();
        processor.process("CERT_ISSUANCE_RESPONSE", JsonMapper.builderWithJackson2Defaults().build().writeValueAsString(response),
                VerifiedAgentMessage.unverified(String.valueOf(org), "CERT_ISSUANCE_RESPONSE", "msg-pg",
                        OffsetDateTime.now()),
                () -> completed.set(true), () -> { });
        return completed.get();
    }

    private boolean scheduleEnabled() {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT enabled FROM renewal_schedule WHERE certificate_xref = ?", Boolean.class, xref));
    }

    private int eventCount(String eventType) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM certificate_events WHERE certificate_xref = ? AND event_type = ?",
                Integer.class, xref, eventType);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
