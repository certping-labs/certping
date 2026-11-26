// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.audit.AuditAsyncWriter;
import com.certmanagement.audit.AuditEventStore;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.dto.cert.CertDeployRequest;
import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.dto.cert.CertRenewalRequest;
import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.dto.cert.RevokeRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.NotificationPublisher;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import com.certmanagement.service.cert.export.CertExportAuditRecorder;
import com.certmanagement.service.cert.export.CertExportFormat;
import com.certmanagement.service.cert.export.CertExportOptions;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.DeploymentTrackingService;
import com.certmanagement.service.deployment.KubernetesDeploymentConfigResolver;
import com.certmanagement.service.scheduler.CertExpiryCleanupService;
import com.certmanagement.service.scheduler.CertExpiryMarkService;
import com.certmanagement.service.scheduler.RenewalTriggerService;
import com.certmanagement.dto.cert.CertExportRequest;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every member-request and job hook of the certificate events on PostgreSQL 15, through the real services, their
 * real transactions ({@code @Transactional} proxies) and the real recorder, store and async writer. Each hook is
 * called the way production calls it, with no transaction open, and must write its row in the change's own
 * transaction: no IllegalTransactionStateException. Each action has exactly one {@code audit_events} customer row.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false",
        "certping.audit.async.flush-interval=50ms", "certping.audit.async.retry-for=1s"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditEventStore.class, AuditAsyncWriter.class, AuditRecorder.class, CertificateAuditRecorder.class,
        com.certmanagement.service.audit.CredentialAuditRecorder.class,
        CertPersistenceService.class, CertIssuanceService.class,
        CertManualIssuanceService.class, CertConversionService.class, CertificateStatusValidator.class,
        RenewalDraftHelper.class, RenewalTriggerService.class, AbandonedRenewalCleanup.class, CertPingDnsKeys.class,
        CertExpiryMarkService.class, CertExpiryCleanupService.class, DeploymentExecutionService.class, CertExportAuditRecorder.class,
        JacksonAutoConfiguration.class, CertificateAuditHooksPostgresTest.Beans.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class CertificateAuditHooksPostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:15-alpine");

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

    @MockitoBean private OrgTypeResolver orgTypeResolver;
    @MockitoBean private CertificateFeatureLocks featureLocks;
    @MockitoBean private CertAgentPublisher publisher;
    @MockitoBean private CredentialReferenceService credentials;
    @MockitoBean private DomainCredentialConfigService domainCredentialConfigs;
    @MockitoBean private KubernetesDeploymentConfigResolver kubernetes;
    @MockitoBean private CertDeploymentConfigService deploymentConfigs;
    @MockitoBean private FeatureFlagService featureFlags;
    @MockitoBean private FeatureFlagResolver featureFlagResolver;
    @MockitoBean private AkamaiSpecialIssuanceService akamai;
    @MockitoBean private NotificationPublisher notifications;
    @MockitoBean private DeploymentTrackingService tracking;

    @Autowired private CertIssuanceService issuance;
    @Autowired private CertPersistenceService persistence;
    @Autowired private CertManualIssuanceService manual;
    @Autowired private CertConversionService conversion;
    @Autowired private RenewalTriggerService renewals;
    @Autowired private CertExpiryMarkService expiry;
    @Autowired private CertExpiryCleanupService cleanup;
    @Autowired private CertExportAuditRecorder exports;
    @Autowired private CertificateAuditRecorder certificateAudit;
    @Autowired private CertificateRepository certificates;
    @Autowired private DomainCredentialConfigRepository domainCredentialConfigRepository;
    @Autowired private AuditEventStore store;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;

    private long org;
    private long udc;
    private long config;
    private int member;
    private int domains;

    @BeforeEach
    void seed() {
        when(featureFlagResolver.resolveUncached(anyString(), any())).thenReturn(true);
        store.createPartition(YearMonth.now(ZoneOffset.UTC));
        store.createPartition(YearMonth.now(ZoneOffset.UTC).plusMonths(1));
        // The jobs claim any eligible row: start each test with none from another.
        jdbc.execute("UPDATE renewal_schedule SET enabled = false");
        jdbc.execute("UPDATE certificates SET deleted_at = now() WHERE deleted_at IS NULL");
        String slug = "acme-" + UUID.randomUUID();
        org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type) VALUES (?, ?, ?, 'B2B')"
                + " RETURNING id", Long.class, slug, slug + ".test", slug);
        member = jdbc.queryForObject("INSERT INTO users (email, display_name, organization_id) VALUES (?, 'Alice', ?)"
                + " RETURNING id", Integer.class, slug + "@acme.test", org);
        udc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'example.com') RETURNING id", Long.class, org);
        config = jdbc.queryForObject("INSERT INTO domain_credential_config (user_domain_cert_id, dns_config,"
                + " deployment_targets) VALUES (?, '{\"example.com\":\"cred-dns\"}'::jsonb, '[]'::jsonb) RETURNING id",
                Long.class, udc);
        when(credentials.getByXref(anyLong(), eq("cred-dns"))).thenReturn(credential("cred-dns", "CLOUDFLARE", "DNS"));
        when(credentials.getByXref(anyLong(), eq("cred-kv"))).thenReturn(credential("cred-kv", "AZURE_KV",
                "DEPLOYMENT"));
        when(orgTypeResolver.resolve(any(Long.class))).thenReturn("B2B");
        when(featureFlags.isEnabled(anyString(), any())).thenReturn(true);
        GatewayRequestContext.set(member, String.valueOf(org), "req-member", "alice@acme.test");
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
        reset(publisher);
    }

    // ── A member's requests: each hook in its change's own transaction ──

    @Test
    void anIssuanceRequest_andItsPublishFailure_areTheMembersRows() {
        issuance.issue(org, issueRequest());
        doThrow(new IllegalStateException("publish refused")).when(publisher).publishIssuance(any());
        assertThatThrownBy(() -> issuance.issue(org, issueRequest())).isInstanceOf(ServiceUnavailableException.class);

        assertThat(rows()).extracting(r -> r.get("event") + "|" + r.get("outcome") + "|" + r.get("error_code"))
                .containsExactly("certificate.issue_requested|SUCCESS|null",
                        "certificate.issue_requested|SUCCESS|null",
                        "certificate.issued|FAILURE|SERVICE_UNAVAILABLE");
        assertThat(rows()).allSatisfy(r -> assertThat(r).containsEntry("actor_type", "USER")
                .containsEntry("actor_user_id", member));
        assertThat(rows().get(0)).containsEntry("summary", "Requested a certificate for example.com from Let's Encrypt");
    }

    @Test
    void deploymentTargetsAnIssuanceOrRenewalReplaces_areTheMembersDeploymentTargetRows() {
        CertIssuanceRequest request = issueRequest("targets.example.com");
        request.setDeploymentTargets(List.of("cred-kv"));
        issuance.issue(org, request);

        CertificateEntity active = certificate("ACTIVE");
        DomainCredentialConfigEntity domainConfig = DomainCredentialConfigEntity.builder()
                .userDomainCertId(active.getUserDomainCertId()).dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of("cred-old")).build();
        persistence.persistRenewal(active, renewalDraft(), domainConfig, List.of("cred-kv"), "ACTIVE", "req-r", null);

        assertThat(rows()).extracting(r -> r.get("event") + "|" + r.get("summary")).startsWith(
                "certificate.issue_requested|Requested a certificate for targets.example.com from Let's Encrypt",
                "deployment_target.added|Added the deployment target for targets.example.com",
                "deployment_target.added|Added the deployment target for " + active.getDomain(),
                "deployment_target.removed|Removed the deployment target from " + active.getDomain());
        assertThat(rows()).extracting(r -> r.get("event")).last().isEqualTo("certificate.renewal_requested");
        assertThat(rows()).allSatisfy(r -> assertThat(r).containsEntry("actor_type", "USER")
                .containsEntry("actor_user_id", member));
    }

    @Test
    void aRenewNowThatFindsARenewalAlreadyStarted_leavesTheDeploymentTargetsAndTheAuditUntouched() {
        CertificateEntity active = certificate("ACTIVE");
        schedule(active.getCertificateXref());
        jdbc.update("UPDATE domain_credential_config SET deployment_targets = '[\"cred-old\"]'::jsonb WHERE id = ?",
                config);
        when(domainCredentialConfigs.getById(config)).thenAnswer(call -> {
            jdbc.update("UPDATE certificates SET status = 'RENEWING' WHERE certificate_xref = ?",
                    active.getCertificateXref());
            return domainCredentialConfigRepository.findById(config).orElseThrow();
        });
        CertRenewalRequest request = new CertRenewalRequest();
        request.setDeploymentTargets(List.of("cred-kv"));

        assertThatThrownBy(() -> issuance.renew(org, active.getCertificateXref(), request))
                .isInstanceOf(DuplicateResourceException.class);

        assertThat(jdbc.queryForObject("SELECT deployment_targets::text FROM domain_credential_config WHERE id = ?",
                String.class, config)).isEqualTo("[\"cred-old\"]");
        assertThat(rows()).isEmpty();
        verify(publisher, never()).publishRenewal(any());
    }

    @Test
    void renewalRevocationAndDeploymentRequests_andTheirFailures_areWrittenInTheirTransactions() {
        CertificateEntity active = certificate("ACTIVE");
        persistence.persistRenewal(active, renewalDraft(), null, null, "ACTIVE", "req-r", null);
        persistence.markRenewalPublishFailed(active.getCertificateXref(), null, org, "ACTIVE", "req-r", null, "x");
        CertificateEntity revocable = certificate("ACTIVE");
        RevokeRequest revoke = new RevokeRequest();
        revoke.setReason("SUPERSEDED");
        persistence.persistRevocation(revocable.getCertificateXref(), org, "ACTIVE", revoke, "req-v", null);
        persistence.markRevocationPublishFailed(revocable.getCertificateXref(), org, "req-v", null, "x");

        CertificateEntity deployable = certificate("ACTIVE");
        doThrow(new IllegalStateException("publish refused")).when(publisher).publishDeployment(any());
        CertDeployRequest deploy = new CertDeployRequest();
        deploy.setDeploymentCredentialXref("cred-kv");
        deploy.setTargetType(TargetType.AZURE_KV);
        assertThatThrownBy(() -> issuance.deploy(org, deployable.getCertificateXref(), deploy))
                .isInstanceOf(ServiceUnavailableException.class);

        await().atMost(Duration.ofSeconds(5)).until(() -> rows().size() == 6);
        assertThat(rows()).extracting(r -> r.get("event") + "|" + r.get("error_code")).containsExactly(
                "certificate.renewal_requested|null", "certificate.renewed|SERVICE_UNAVAILABLE",
                "certificate.revoke_requested|null", "certificate.revoked|SERVICE_UNAVAILABLE",
                "deployment.requested|null", "deployment.failed|SERVICE_UNAVAILABLE");
        assertThat(rows()).allSatisfy(r -> assertThat(r).containsEntry("actor_type", "USER"));
        assertThat(rows().get(4)).containsEntry("summary",
                "Started deploying the certificate for " + deployable.getDomain() + " to Azure Key Vault");
    }

    @Test
    void deletes_andAManagedDomainsDelete_writeOneRowPerCertificate() {
        CertificateEntity single = certificate("FAILED");
        issuance.delete(org, single.getCertificateXref());
        long otherUdc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'shop.example.com') RETURNING id", Long.class, org);
        certificate("ACTIVE", otherUdc);
        certificate("PENDING", otherUdc);

        issuance.deleteUserDomainCert(org, otherUdc);

        assertThat(rows()).extracting(r -> r.get("event") + "|" + r.get("summary")).containsExactly(
                "certificate.deleted|Deleted the certificate for " + single.getDomain(),
                "certificate.deleted|Deleted the certificate for shop.example.com",
                "certificate.deleted|Deleted the certificate for shop.example.com");
        assertThat(details(1)).contains("\"source\": \"MANAGED_DOMAIN\"");
        assertThat(details(0)).doesNotContain("source");
    }

    @Test
    void manualIssuance_dnsValidation_andConversion_writeTheirRows() {
        IssueManualRequest request = new IssueManualRequest();
        request.setDomain("manual.example.com");
        CertificateEntity started = manual.initiateManualIssuance(org, request);
        jdbc.update("UPDATE certificates SET status = 'AWAITING_DNS' WHERE certificate_xref = ?",
                started.getCertificateXref());
        jdbc.update("INSERT INTO cert_manual_issuance_state (cert_xref, organization_id, acme_order_url,"
                + " acme_account_handle, txt_records, created_at, expires_at) VALUES (?, ?, 'https://acme/o/1',"
                + " 'https://kv.example/secrets/acme', '[]'::jsonb, now(), now() + interval '1 hour')",
                started.getCertificateXref(), org);
        manual.triggerValidation(started.getCertificateXref(), org);

        CertificateEntity active = certificate("ACTIVE");
        ConvertToAutomatedRequest convert = new ConvertToAutomatedRequest();
        ConvertToAutomatedRequest.DnsCredentialMapping mapping = new ConvertToAutomatedRequest.DnsCredentialMapping();
        mapping.setDomain("example.com");
        mapping.setCredentialXref("cred-dns");
        convert.setDnsMappings(List.of(mapping));
        conversion.convertToAutomated(org, active.getCertificateXref(), convert);

        assertThat(rows()).extracting(r -> r.get("summary")).containsExactly(
                "Started a manual issuance of a certificate for manual.example.com from Let's Encrypt",
                "Confirmed the DNS records for manual.example.com were added and started validation",
                "Switched the certificate for " + active.getDomain() + " to automatic renewal");
        assertThat(rows()).allSatisfy(r -> assertThat(r).containsEntry("actor_type", "USER"));
    }

    @Test
    void aManualIssuanceTheAgentNeverGot_rollsBackItsRowWithIt() {
        doThrow(new IllegalStateException("publish refused")).when(publisher).publishManualTxtRequest(any(), any(), any(),
                any(), any());
        IssueManualRequest request = new IssueManualRequest();
        request.setDomain("manual.example.com");

        assertThatThrownBy(() -> manual.initiateManualIssuance(org, request))
                .isInstanceOf(ServiceUnavailableException.class);

        assertThat(rows()).as("the request's failure is its @AuditFailure row, not a success").isEmpty();
    }

    // ── CertPing's jobs ─────────────────────────────────────────────────

    @Test
    void theRenewalJob_startsOrSkipsEachCertificate_asCertPing() {
        GatewayRequestContext.clear();
        CertificateEntity due = certificate("ACTIVE");
        schedule(due.getCertificateXref());
        assertThat(renewals.tryProcessOneEligible()).isTrue();

        CertificateEntity caOff = certificate("ACTIVE");
        caOff.setCaProvider(CaProvider.DIGICERT);
        jdbc.update("UPDATE certificates SET ca_provider = 'DIGICERT' WHERE certificate_xref = ?",
                caOff.getCertificateXref());
        schedule(caOff.getCertificateXref());
        when(featureFlags.isEnabled(eq("DIGICERT"), any())).thenReturn(false);
        assertThat(renewals.tryProcessOneEligible()).isTrue();

        CertificateEntity failing = certificate("ACTIVE");
        schedule(failing.getCertificateXref());
        doThrow(new IllegalStateException("publish refused", new IllegalArgumentException("message rejected before sending")))
                .when(publisher).publishRenewal(any());
        assertThat(renewals.tryProcessOneEligible()).isTrue();

        // Every pod runs the job: the CA-off skip's window is shared through the trail, not kept per pod.
        jdbc.update("UPDATE renewal_schedule SET next_attempt_at = now() - interval '1 minute' "
                + "WHERE certificate_xref = ?", caOff.getCertificateXref());
        assertThat(renewals.tryProcessOneEligible()).as("the same certificate, claimed again").isTrue();

        assertThat(rows()).extracting(r -> r.get("event") + "|" + r.get("error_code")).containsExactly(
                "certificate.auto_renewal_started|null",
                "certificate.auto_renewal_skipped|FEATURE_OFF",
                "certificate.auto_renewal_started|null",
                "certificate.renewed|RENEWAL_TRIGGER_FAILED");
        assertThat(rows()).allSatisfy(r -> assertThat(r).containsEntry("actor_type", "SYSTEM")
                .containsEntry("actor_job", "trigger-renewals"));
        assertThat(rows().get(1)).containsEntry("summary", "Skipped renewing the certificate for "
                + caOff.getDomain() + " automatically because the feature 'DigiCert' is off");
    }

    @Test
    void expiryAndCleanup_areCertPingsRows() {
        GatewayRequestContext.clear();
        CertificateEntity expiring = certificate("ACTIVE");
        jdbc.update("UPDATE certificates SET valid_to = now() - interval '1 hour' WHERE certificate_xref = ?",
                expiring.getCertificateXref());
        assertThat(expiry.tryProcessOneEligible()).isTrue();

        CertificateEntity stale = certificate("REVOKED");
        jdbc.update("UPDATE certificates SET updated_at = now() - interval '2 days' WHERE certificate_xref = ?",
                stale.getCertificateXref());
        assertThat(cleanup.tryProcessOneEligible()).isTrue();

        assertThat(rows()).extracting(r -> r.get("summary") + "|" + r.get("actor_job")).containsExactly(
                "The certificate for " + expiring.getDomain() + " expired|mark-expired-certs",
                "Deleted the certificate for " + stale.getDomain() + "|expiry-cleanup");
        assertThat(details(1)).contains("\"source\": \"EXPIRY_CLEANUP\"");
    }

    // ── The rows need the change's transaction ──────────────────────────

    @Test
    void outsideATransactionTheHooksRefuseToWrite() {
        CertificateEntity cert = certificate("ACTIVE");

        assertThatThrownBy(() -> certificateAudit.deleted(cert, null, "ACTIVE"))
                .isInstanceOf(IllegalTransactionStateException.class);
        try (AuditScope scope = AuditScope.system("agent-response", org)) {
            assertThatThrownBy(() -> certificateAudit.deploymentSucceeded(cert, "AZURE_KV", null, null))
                    .isInstanceOf(IllegalTransactionStateException.class);
        }
        assertThat(rows()).isEmpty();
    }

    // ── One row per action ──────────────────────────────────────────────

    @Test
    void everyActionHasExactlyOneCustomerRow() throws Exception {
        CertificateEntity cert = certificate("ACTIVE");
        issuance.issue(org, issueRequest("issued.example.com"));
        issuance.delete(org, certificate("FAILED").getCertificateXref());
        try (CertExportOptions options = CertExportOptions.from(new CertExportRequest("FULLCHAIN_PEM", null, null))) {
            new TransactionTemplate(transactionManager).executeWithoutResult(status ->
                    exports.recordExport(cert, options));
        }
        exports.recordRefusal(org, cert, CertExportFormat.PKCS12, "CERT_MATERIAL_GONE");
        exports.recordNotFound(org, CertExportFormat.FULLCHAIN_PEM, "cert-elsewhere");

        await().atMost(Duration.ofSeconds(5)).until(() -> count("SELECT count(*) FROM audit_events "
                + "WHERE event = 'access.certificate_export_refused' AND organization_id = " + org) == 1);
        await().during(Duration.ofMillis(300)).atMost(Duration.ofSeconds(3)).until(() -> true);

        assertThat(jdbc.queryForList("SELECT event FROM audit_events WHERE organization_id = ? AND visibility = "
                + "'CUSTOMER' ORDER BY id", String.class, org)).containsExactly("certificate.issue_requested",
                "certificate.deleted", "certificate.exported", "certificate.exported",
                "access.certificate_export_refused");
        assertThat(jdbc.queryForList("SELECT outcome || '|' || coalesce(error_code, '-') FROM audit_events WHERE "
                + "organization_id = ? AND event = 'certificate.exported' ORDER BY id", String.class, org))
                .containsExactly("SUCCESS|-", "FAILURE|CERT_MATERIAL_GONE");
        // A refusal that resolved no certificate is the access event, never also a certificate.exported row.
        assertThat(jdbc.queryForList("SELECT outcome || '|' || error_code || '|' || category || '|' || resource_ref "
                + "FROM audit_events WHERE organization_id = ? AND event = 'access.certificate_export_refused'",
                String.class, org)).containsExactly("FAILURE|NOT_FOUND|ACCESS|cert-elsewhere");
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private CertIssuanceRequest issueRequest() {
        return issueRequest("example.com");
    }

    private CertIssuanceRequest issueRequest(String domain) {
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDomain(domain);
        request.setCaProvider(CaProvider.LETS_ENCRYPT);
        request.setDnsCredentialXref("cred-dns");
        return request;
    }

    /**
     * A certificate in {@code status} on a managed domain of its own ({@code cN.example.com}): one active certificate
     * per domain, one domain per name in an organization.
     */
    private CertificateEntity certificate(String status) {
        long own = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, ?) RETURNING id", Long.class, org, "c" + (++domains) + ".example.com");
        return certificate(status, own);
    }

    private CertificateEntity certificate(String status, long userDomainCertId) {
        String xref = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status, valid_to,"
                + " cert_secret_handle) VALUES (?, ?, 'LETS_ENCRYPT', ?, now() + interval '60 days', ?)", xref,
                userDomainCertId, status, "https://kv.example/secrets/" + xref);
        return certificates.findByCertificateXref(xref).orElseThrow();
    }

    private CertificateEntity renewalDraft() {
        return CertificateEntity.builder().certificateXref("cert-" + UUID.randomUUID()).userDomainCertId(udc)
                .caProvider(CaProvider.LETS_ENCRYPT).status("PENDING").build();
    }

    /** An enabled renewal schedule due now. */
    private void schedule(String xref) {
        jdbc.update("INSERT INTO renewal_schedule (certificate_xref, domain_credential_config_id, valid_to,"
                + " renewal_eligible_at, ca_provider, enabled, cert_secret_handle) VALUES (?, ?, now() + interval"
                + " '20 days', now() - interval '1 minute', 'LETS_ENCRYPT', TRUE, ?)", xref, config,
                "https://kv.example/secrets/" + xref);
    }

    private static CredentialReferenceEntity credential(String xref, String provider, String type) {
        return CredentialReferenceEntity.builder().id((long) Math.abs(xref.hashCode())).credentialXref(xref)
                .provider(provider).type(type).status("ACTIVE").secretHandle("https://kv.example/secrets/" + xref)
                .build();
    }

    private List<Map<String, Object>> rows() {
        return jdbc.queryForList("SELECT event, outcome, error_code, summary, actor_type, actor_user_id, actor_job "
                + "FROM audit_events WHERE organization_id = ? AND visibility = 'CUSTOMER' ORDER BY id", org);
    }

    private String details(int index) {
        return jdbc.queryForList("SELECT details::text FROM audit_events WHERE organization_id = ? AND visibility = "
                + "'CUSTOMER' ORDER BY id", String.class, org).get(index);
    }

    private int count(String sql) {
        Integer count = jdbc.queryForObject(sql, Integer.class);
        return count == null ? 0 : count;
    }
}
