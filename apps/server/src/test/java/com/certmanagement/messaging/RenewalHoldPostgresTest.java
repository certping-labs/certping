// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.testing.LogCapture;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.RenewalStatus;
import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateCryptoMetadataRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewScope;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import com.certmanagement.service.cert.AkamaiSpecialIssuanceService;
import com.certmanagement.service.cert.CertPingDnsKeys;
import com.certmanagement.service.cert.CertificateStatusValidator;
import com.certmanagement.service.cert.CredentialReferenceService;
import com.certmanagement.service.cert.RenewalDraftHelper;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.DeploymentExecutionService.AutoDeployOutcome;
import com.certmanagement.service.lifecycle.BlockerKind;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import com.certmanagement.service.lifecycle.HeldRenewalsLifecycle;
import com.certmanagement.service.scheduler.RenewalTriggerService;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import com.certmanagement.service.scheduler.StalledRenewalRecoveryService;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import tools.jackson.databind.json.JsonMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
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

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Renewal holds on real PostgreSQL with the real renewal trigger, the real agent-response handling and
 * the real flag resolver: a switch-off never loses a renewal in flight (its outcome rewrites the
 * schedule, so the hold is taken at the next claim instead, and released on turn-on), and automatic
 * renewal, which needs both CERTIFICATE_RENEWAL and DNS_CREDENTIALS, starts only while both are on.
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({FeatureLifecycleLock.class, FeatureFlagResolver.class, CertificateLifecycleRepository.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class RenewalHoldPostgresTest {

    private static final String RENEWAL = FeatureFlags.CERTIFICATE_RENEWAL;
    private static final String DNS = FeatureFlags.DNS_CREDENTIALS;

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
    @Autowired private UserDomainCertRepository userDomainCerts;
    @Autowired private CertManualIssuanceStateRepository manualStates;
    @Autowired private CertificateCryptoMetadataRepository cryptoMetadata;
    @Autowired private DeploymentRepository deployments;
    @Autowired private CredentialReferenceRepository credentials;
    @Autowired private FeatureLifecycleLock lock;
    @Autowired private FeatureFlagResolver resolver;
    @Autowired private CertificateLifecycleRepository certificateLifecycle;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private TransactionTemplate transactions;

    private final CertAgentPublisher publisher = mock(CertAgentPublisher.class);
    private final CertificateStatusValidator statusValidator = mock(CertificateStatusValidator.class);
    private final DeploymentExecutionService deployer = mock(DeploymentExecutionService.class);
    private CertResponseProcessor processor;
    private RenewalTriggerService trigger;
    private HeldRenewalsLifecycle renewal;
    private final CertificateAuditRecorder audit = mock(CertificateAuditRecorder.class);
    private long org;
    private long udc;
    private String current;


    @BeforeEach
    void seed() {
        jdbc.execute("TRUNCATE renewal_schedule, certificates, domain_credential_config, user_domain_certificate,"
                + " credential_references CASCADE");
        String slug = "org-" + UUID.randomUUID();
        org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, 'B2B') RETURNING id", Long.class, slug, slug + ".test", slug);
        udc = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'example.com') RETURNING id", Long.class, org);
        long config = jdbc.queryForObject("INSERT INTO domain_credential_config (user_domain_cert_id, dns_config,"
                + " deployment_targets) VALUES (?, '{\"example.com\": \"cred-dns\"}'::jsonb, '[]'::jsonb)"
                + " RETURNING id", Long.class, udc);
        current = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status, valid_to)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', 'ACTIVE', NOW() + INTERVAL '5 days')", current, udc);
        jdbc.update("INSERT INTO renewal_schedule (certificate_xref, domain_credential_config_id, valid_to,"
                + " renewal_eligible_at, ca_provider, enabled) VALUES (?, ?, NOW() + INTERVAL '5 days',"
                + " NOW() - INTERVAL '1 day', 'LETS_ENCRYPT', TRUE)", current, config);

        renewal = new HeldRenewalsLifecycle(RENEWAL, BlockerKind.AUTO_RENEW_CERTS, "Automatic renewals",
                AutoRenewScope.everyCa(), RenewalStatus.FEATURE_HOLD.name(), certificateLifecycle);
        FeatureFlagService flags = mock(FeatureFlagService.class);
        when(flags.isEnabled(anyString(), anyLong())).thenReturn(true);
        trigger = new RenewalTriggerService(schedules, certificates, events, credConfigs, userDomainCerts,
                mock(CredentialReferenceService.class), publisher, statusValidator, new RenewalDraftHelper(), flags,
                mock(AkamaiSpecialIssuanceService.class), mock(OrgTypeResolver.class), audit, resolver,
                new AbandonedRenewalCleanup(certificates, schedules),
                new CertPingDnsKeys(credentials, JsonMapper.builderWithJackson2Defaults().findAndAddModules().build()));

        when(deployer.planAutoDeploy(any(), anyBoolean())).thenReturn(AutoDeployOutcome.NOTHING_TO_DEPLOY);
        processor = PostgresCertResponses.processor(certificates, cryptoMetadata, events, schedules, credConfigs,
                manualStates, credentials, deployments, deployer, transactions, lock, resolver);
    }

    /**
     * IN_PROGRESS: a manual or scheduled renewal awaiting the agent. FAILED: an earlier attempt failed
     * while the agent still retries it, so only the certificate (RENEWING) shows it is in flight.
     */
    @ParameterizedTest
    @ValueSource(strings = {"IN_PROGRESS", "FAILED"})
    void aSwitchOffDuringASuccessfulRenewalHoldsTheScheduleAtTheNextClaimAndTurnOnReleasesIt(String scheduleStatus)
            throws Exception {
        String draft = renewalInFlight(scheduleStatus);

        switchOff(RENEWAL);
        assertThat(renewal.platformPause(org)).as("a renewal in flight is left alone").isEmpty();
        assertThat(state()).isEqualTo("true:" + scheduleStatus);

        deliverRenewalSuccess(draft);
        current = draft;
        assertThat(state()).isEqualTo("true:SUCCESS");

        makeDue();
        claimAndProcess();
        assertThat(state()).isEqualTo("true:FEATURE_HOLD");

        switchOn(RENEWAL);
        renewal.platformResume(org);
        assertThat(state()).isEqualTo("true:null");
        verify(publisher, never()).publishRenewal(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"IN_PROGRESS", "FAILED"})
    void aSwitchOffDuringAFailedRenewalHoldsTheScheduleAtTheNextClaimAndTurnOnReleasesIt(String scheduleStatus)
            throws Exception {
        String draft = renewalInFlight(scheduleStatus);

        switchOff(RENEWAL);
        assertThat(renewal.platformPause(org)).isEmpty();

        deliverRenewalFailure(draft);
        assertThat(state()).isEqualTo("true:FAILED");

        makeDue();
        claimAndProcess();
        assertThat(state()).isEqualTo("true:FEATURE_HOLD");

        switchOn(RENEWAL);
        renewal.platformResume(org);
        assertThat(state()).isEqualTo("true:null");
        verify(publisher, never()).publishRenewal(any());
    }

    /** A manual "Renew now" during a hold, whatever its outcome, keeps the hold, so turning back on re-enables it. */
    @ParameterizedTest
    @CsvSource({"CERTIFICATE_RENEWAL, true", "CERTIFICATE_RENEWAL, false", "DNS_CREDENTIALS, true",
            "DNS_CREDENTIALS, false"})
    void aManualRenewalDuringAHoldKeepsTheHoldAndTurningBackOnReEnablesTheSchedule(String featureKey,
                                                                                    boolean succeeds)
            throws Exception {
        switchOff(featureKey);
        renewal.platformPause(org);
        assertThat(state()).isEqualTo("false:FEATURE_HOLD");

        String draft = manualRenewalStarted();
        if (succeeds) {
            deliverRenewalSuccess(draft);
            current = draft;
        } else {
            deliverRenewalFailure(draft);
        }
        assertThat(state()).as("the outcome keeps the hold, and the schedule off").isEqualTo("false:FEATURE_HOLD");

        switchOn(featureKey);
        renewal.platformResume(org);
        assertThat(state()).isEqualTo("true:null");
    }

    /** Turned back on while a manual renewal is in flight: the outcome then writes the status as usual. */
    @ParameterizedTest
    @CsvSource({"CERTIFICATE_RENEWAL, true", "CERTIFICATE_RENEWAL, false", "DNS_CREDENTIALS, true",
            "DNS_CREDENTIALS, false"})
    void aTurnOnDuringAManualRenewalReleasesTheScheduleAndTheOutcomeTakesItFromThere(String featureKey,
                                                                                      boolean succeeds)
            throws Exception {
        switchOff(featureKey);
        renewal.platformPause(org);
        String draft = manualRenewalStarted();

        switchOn(featureKey);
        renewal.platformResume(org);
        assertThat(state()).as("released although the certificate is RENEWING").isEqualTo("true:null");

        if (succeeds) {
            deliverRenewalSuccess(draft);
            current = draft;
            assertThat(state()).isEqualTo("true:SUCCESS");
        } else {
            deliverRenewalFailure(draft);
            assertThat(state()).isEqualTo("true:FAILED");
            assertThat(jdbc.queryForObject("SELECT next_attempt_at IS NOT NULL FROM renewal_schedule"
                    + " WHERE certificate_xref = ?", Boolean.class, current)).isTrue();
        }
    }

    @Test
    void dnsCredentialsOffHoldsTheDueRenewalUnderItsOwnKey_andTurningThemOnLetsItRun() {
        switchOff(DNS);
        makeDue();
        claimAndProcess();
        assertThat(state()).isEqualTo("true:FEATURE_HOLD");
        verify(audit).autoRenewalSkippedByJob(any(), eq(DNS));

        switchOn(DNS);
        makeDue();
        claimAndProcess();
        assertThat(state()).as("past the hold, at the certificate check").isEqualTo("true:FAILED");
    }

    /**
     * An expired CertPing DNS key holds the renewal, checked again while it stays expired and audited once;
     * renewing the key, which updates its credential, rearms the schedule at once.
     */
    @Test
    void anExpiredCertPingDnsKeyHoldsTheRenewal_andRenewingTheKeyRearmsIt() {
        jdbc.update("INSERT INTO credential_references (credential_xref, organization_id, provider, type, status,"
                + " secret_handle, config) VALUES ('cred-dns', ?, 'CERTPING', 'DNS', 'ACTIVE',"
                + " 'https://kv.test/secrets/x', CAST(? AS jsonb))", org,
                "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"2026-01-01T00:00:00Z\"}");
        makeDue();
        claimAndProcess();
        assertThat(state()).isEqualTo("true:DNS_KEY_EXPIRED_HOLD");

        makeDue();
        claimAndProcess();
        assertThat(state()).as("still held while the key is expired").isEqualTo("true:DNS_KEY_EXPIRED_HOLD");
        verify(audit, times(1)).autoRenewalHeldByExpiredDnsKey(any(), eq(Instant.parse("2026-01-01T00:00:00Z")));

        jdbc.update("UPDATE renewal_schedule SET next_attempt_at = NOW() + INTERVAL '1 hour' WHERE certificate_xref = ?",
                current);
        jdbc.update("UPDATE credential_references SET config = CAST(? AS jsonb) WHERE credential_xref = 'cred-dns'",
                "{\"tokenId\":42,\"tokenPrefix\":\"cpk_live_cd34ef56\",\"expiresAt\":\"2099-01-01T00:00:00Z\"}");
        Integer rearmed = transactions.execute(status -> schedules.rearmParkedFailuresByDnsCredentialXref("cred-dns"));
        assertThat(rearmed).isEqualTo(1);
        claimAndProcess();
        assertThat(state()).as("past the hold, at the certificate check").isEqualTo("true:FAILED");
    }

    /** A key the configuration holds for a name the certificate does not have never holds its renewal. */
    @Test
    void anExpiredCertPingDnsKeyTheRenewalDoesNotUse_doesNotHoldIt() {
        jdbc.update("UPDATE domain_credential_config SET dns_config = CAST(? AS jsonb)",
                "{\"example.com\": \"cred-dns\", \"unused.org\": \"cred-unused\"}");
        jdbc.update("INSERT INTO credential_references (credential_xref, organization_id, provider, type, status,"
                + " secret_handle, config) VALUES ('cred-unused', ?, 'CERTPING', 'DNS', 'ACTIVE',"
                + " 'https://kv.test/secrets/x', CAST(? AS jsonb))", org,
                "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"2026-01-01T00:00:00Z\"}");
        makeDue();
        claimAndProcess();

        assertThat(state()).as("past the key check, at the certificate check").isEqualTo("true:FAILED");
        verify(audit, never()).autoRenewalHeldByExpiredDnsKey(any(), any());
    }

    /** Binding the domain to another credential (a per-domain PATCH) releases the hold at once. */
    @Test
    void anExpiredCertPingDnsKeyHold_isReleasedWhenTheDomainIsBoundAnew() {
        jdbc.update("INSERT INTO credential_references (credential_xref, organization_id, provider, type, status,"
                + " secret_handle, config) VALUES ('cred-dns', ?, 'CERTPING', 'DNS', 'ACTIVE',"
                + " 'https://kv.test/secrets/x', CAST(? AS jsonb))", org,
                "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"2026-01-01T00:00:00Z\"}");
        makeDue();
        claimAndProcess();
        assertThat(state()).isEqualTo("true:DNS_KEY_EXPIRED_HOLD");

        long config = jdbc.queryForObject("SELECT domain_credential_config_id FROM renewal_schedule"
                + " WHERE certificate_xref = ?", Long.class, current);
        Integer rearmed = transactions.execute(status -> schedules.rearmParkedFailuresByDomainCredentialConfigId(config));

        assertThat(rearmed).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT next_attempt_at <= NOW() FROM renewal_schedule WHERE certificate_xref = ?",
                Boolean.class, current)).isTrue();
    }

    @Test
    void bothOff_noRenewalStartsUntilBothAreOn() {
        switchOff(DNS);
        switchOff(RENEWAL);
        makeDue();
        claimAndProcess();
        assertThat(state()).isEqualTo("true:FEATURE_HOLD");

        switchOn(RENEWAL);
        makeDue();
        claimAndProcess();
        assertThat(state()).as("DNS credentials still off").isEqualTo("true:FEATURE_HOLD");

        switchOn(DNS);
        makeDue();
        claimAndProcess();
        assertThat(state()).as("past both holds, at the certificate check").isEqualTo("true:FAILED");
    }

    /** What a manual renewal leaves before the agent answers: the certificate RENEWING and a PENDING draft. */
    private String manualRenewalStarted() {
        String draft = "cert-" + UUID.randomUUID();
        jdbc.update("UPDATE certificates SET status = 'RENEWING' WHERE certificate_xref = ?", current);
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', 'PENDING')", draft, udc);
        return draft;
    }

    /** The certificate is RENEWING, its schedule at {@code scheduleStatus}, and a PENDING draft awaits the agent. */
    private String renewalInFlight(String scheduleStatus) {
        String draft = "cert-" + UUID.randomUUID();
        jdbc.update("UPDATE certificates SET status = 'RENEWING' WHERE certificate_xref = ?", current);
        jdbc.update("UPDATE renewal_schedule SET last_renewal_status = ? WHERE certificate_xref = ?",
                scheduleStatus, current);
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', 'PENDING')", draft, udc);
        return draft;
    }

    @Test
    void aResultArrivingAfterTheAttemptWasEnded_isCountedAndNotApplied() throws Exception {
        String draft = renewalInFlight("IN_PROGRESS");
        jdbc.update("UPDATE certificates SET created_at = NOW() - INTERVAL '200 hours' WHERE certificate_xref = ?",
                draft);
        StalledRenewalRecoveryService sweep = new StalledRenewalRecoveryService(certificates, schedules, events,
                new AbandonedRenewalCleanup(certificates, schedules), audit, new SimpleMeterRegistry());
        Boolean swept = transactions.execute(status -> sweep.tryProcessOneEligible());
        assertThat(swept).isTrue();
        SimpleMeterRegistry late = new SimpleMeterRegistry();
        Metrics.addRegistry(late);
        try (LogCapture logs = LogCapture.of(CertResponseProcessor.class)) {
            deliverRenewalSuccess(draft, "REPLACEMENT");

            assertThat(late.counter(AbandonedRenewalCleanup.RESULT_AFTER_TIMEOUT_METRIC, "kind", "renewal").count())
                    .isEqualTo(1);
            assertThat(logs.messages()).anySatisfy(message -> assertThat(message)
                    .startsWith("[RENEWAL_RESULT_AFTER_TIMEOUT] xref=" + draft)
                    .contains("serial=04:AB:CE", "caOrderAction=REPLACEMENT"));
        } finally {
            Metrics.removeRegistry(late);
        }
        assertThat(jdbc.queryForObject("SELECT status FROM certificates WHERE certificate_xref = ?", String.class,
                draft)).isEqualTo("RENEWAL_FAILED");
        assertThat(jdbc.queryForObject("SELECT status FROM certificates WHERE certificate_xref = ?", String.class,
                current)).isEqualTo("ACTIVE");
        assertThat(state()).isEqualTo("true:FAILED");
    }

    @Test
    void aSuccessfulRenewalStartsTheFailureCountAgain() throws Exception {
        String draft = renewalInFlight("IN_PROGRESS");
        jdbc.update("UPDATE renewal_schedule SET consecutive_failures = 3 WHERE certificate_xref = ?", current);

        deliverRenewalSuccess(draft);

        assertThat(jdbc.queryForObject("SELECT consecutive_failures FROM renewal_schedule WHERE certificate_xref = ?",
                Integer.class, draft)).isZero();
    }

    @Test
    void aFailedRenewalCountsOneMoreFailureAndBacksOff() throws Exception {
        String draft = renewalInFlight("IN_PROGRESS");
        jdbc.update("UPDATE renewal_schedule SET consecutive_failures = 1 WHERE certificate_xref = ?", current);

        deliverRenewalFailure(draft);

        assertThat(jdbc.queryForObject("SELECT consecutive_failures || ':' || (next_attempt_at >= NOW() + INTERVAL"
                + " '59 minutes') FROM renewal_schedule WHERE certificate_xref = ?", String.class, current))
                .isEqualTo("2:true");
    }

    @Test
    void aCertificateIssuedWhileRenewalIsOffIsHeldByTheTrigger_andRunsOnceRenewalIsBackOn() throws Exception {
        jdbc.update("UPDATE renewal_schedule SET enabled = FALSE WHERE certificate_xref = ?", current);
        switchOff(RENEWAL);
        long entry = jdbc.queryForObject("INSERT INTO user_domain_certificate (organization_id, domain)"
                + " VALUES (?, 'issued.example.com') RETURNING id", Long.class, org);
        long config = jdbc.queryForObject("INSERT INTO domain_credential_config (user_domain_cert_id,"
                + " deployment_targets) VALUES (?, '[]'::jsonb) RETURNING id", Long.class, entry);
        String issued = "cert-" + UUID.randomUUID();
        jdbc.update("INSERT INTO certificates (certificate_xref, user_domain_cert_id, ca_provider, status)"
                + " VALUES (?, ?, 'LETS_ENCRYPT', 'PENDING')", issued, entry);
        jdbc.update("INSERT INTO renewal_schedule (certificate_xref, domain_credential_config_id, valid_to,"
                + " renewal_eligible_at, ca_provider, enabled) VALUES (?, ?, NOW(), NOW(), 'LETS_ENCRYPT', FALSE)",
                issued, config);

        PostgresCertResponses.deliverIssued(processor, org, issued);
        assertThat(stateOf(issued)).isEqualTo("true:FEATURE_HOLD");
        makeDue(issued);
        claimAndProcess();
        assertThat(stateOf(issued)).as("renewal still off").isEqualTo("true:FEATURE_HOLD");

        switchOn(RENEWAL);
        makeDue(issued);
        claimAndProcess();
        assertThat(stateOf(issued)).as("past the hold, at the certificate check").isEqualTo("true:FAILED");
    }

    private String stateOf(String xref) {
        return jdbc.queryForObject("SELECT enabled || ':' || COALESCE(last_renewal_status, 'null')"
                + " FROM renewal_schedule WHERE certificate_xref = ?", String.class, xref);
    }

    private void deliverRenewalSuccess(String draft) throws Exception {
        deliverRenewalSuccess(draft, null);
    }

    private void deliverRenewalSuccess(String draft, String caOrderAction) throws Exception {
        CertIssuanceResponse response = new CertIssuanceResponse();
        response.setCaOrderAction(caOrderAction);
        response.setRequestId("req-" + draft);
        response.setOrganizationId(String.valueOf(org));
        response.setCertificateXref(draft);
        response.setStatus("RENEWED");
        response.setCaProvider(CaProvider.LETS_ENCRYPT);
        response.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");
        response.setSerialNumber("04:AB:CE");
        response.setValidFrom(OffsetDateTime.now().toString());
        response.setValidTo(OffsetDateTime.now().plusDays(90).toString());
        PostgresCertResponses.deliver(processor, org, "CERT_ISSUANCE_RESPONSE",
                new tools.jackson.databind.json.JsonMapper().writeValueAsString(response));
    }

    private void deliverRenewalFailure(String draft) throws Exception {
        AgentErrorMessage error = new AgentErrorMessage();
        error.setRequestId("req-" + draft);
        error.setOrganizationId(String.valueOf(org));
        error.setCertificateXref(draft);
        error.setOriginalMessageType("CERT_RENEWAL");
        error.setErrorCode("ACME_ERROR");
        error.setErrorDetail("injected");
        PostgresCertResponses.deliver(processor, org, "AGENT_ERROR", new tools.jackson.databind.json.JsonMapper().writeValueAsString(error));
    }

    private void claimAndProcess() {
        when(statusValidator.isEligibleForScheduledRenewal(any(), anyString())).thenReturn(false);
        Boolean claimed = transactions.execute(status -> trigger.tryProcessOneEligible());
        assertThat(claimed).isTrue();
    }

    /** Time passes: the schedule and any retry of it are due. */
    private void makeDue() {
        makeDue(current);
    }

    private void makeDue(String xref) {
        jdbc.update("UPDATE renewal_schedule SET renewal_eligible_at = NOW() - INTERVAL '1 hour',"
                + " next_attempt_at = CASE WHEN next_attempt_at IS NULL THEN NULL ELSE NOW() - INTERVAL '1 minute' END"
                + " WHERE certificate_xref = ?", xref);
    }

    private void switchOff(String featureKey) {
        jdbc.update("INSERT INTO organization_feature_flags (organization_id, feature_key, enabled, admin_locked)"
                + " VALUES (?, ?, FALSE, TRUE)", org, featureKey);
    }

    private void switchOn(String featureKey) {
        jdbc.update("DELETE FROM organization_feature_flags WHERE organization_id = ? AND feature_key = ?",
                org, featureKey);
    }

    private String state() {
        return jdbc.queryForObject("SELECT enabled || ':' || COALESCE(last_renewal_status, 'null')"
                + " FROM renewal_schedule WHERE certificate_xref = ?", String.class, current);
    }
}
