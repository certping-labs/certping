// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertRenewalCommand;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import com.certmanagement.service.cert.AkamaiSpecialIssuanceService;
import com.certmanagement.service.cert.CertPingDnsKeys;
import com.certmanagement.service.cert.CertificateStatusValidator;
import com.certmanagement.service.cert.CredentialReferenceService;
import com.certmanagement.service.cert.RenewalDraftHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RenewalTriggerServiceTest {

    @Mock private RenewalScheduleRepository        renewalScheduleRepository;
    @Mock private CertificateRepository            certificateRepository;
    @Mock private CertificateEventRepository       certEventRepository;
    @Mock private DomainCredentialConfigRepository domainCredConfigRepository;
    @Mock private UserDomainCertRepository         udcRepository;
    @Mock private CredentialReferenceService       credentialService;
    @Mock private CertAgentPublisher               publisher;
    @Mock private CertificateStatusValidator       certificateStatusValidator;
    @Mock private FeatureFlagService               featureFlagService;
    @Mock private AkamaiSpecialIssuanceService     akamaiSpecialIssuanceService;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;
    @Mock private com.certmanagement.service.audit.CertificateAuditRecorder certificateAudit;
    @Mock private com.certmanagement.service.FeatureFlagResolver featureFlagResolver;
    @Mock private CertPingDnsKeys certPingDnsKeys;
    private final RenewalDraftHelper renewalDraftHelper = new RenewalDraftHelper();

    private RenewalTriggerService service;
    private long idCounter = 100;

    private static final Long   ORGANIZATION_ID = 1L;
    private static final Long   CONFIG_ID = 2L;
    private static final String XREF      = "cert-abc123";

    /** Captured when canonicalSanCert() is built so the lenient UDC mock can return its domain. */
    private Long canonicalUdcId;

    @BeforeEach
    void setUp() {
        service = new RenewalTriggerService(
                renewalScheduleRepository,
                certificateRepository,
                certEventRepository,
                domainCredConfigRepository,
                udcRepository,
                credentialService,
                publisher,
                certificateStatusValidator,
                renewalDraftHelper,
                featureFlagService,
                akamaiSpecialIssuanceService,
                orgTypeResolver,
                certificateAudit,
                featureFlagResolver,
                new AbandonedRenewalCleanup(certificateRepository, renewalScheduleRepository),
                certPingDnsKeys);
        lenient().when(orgTypeResolver.resolve(any(Long.class))).thenReturn("B2B");
        // Default all CA flags to enabled so existing tests aren't affected. Lenient because
        // tests that exit early (empty queue, cert not found) never reach featureFlagService.
        lenient().when(featureFlagService.isEnabled(any(), any())).thenReturn(true);

        // Lenient UDC mock — only tests that reach the renewal codepath actually invoke this.
        // canonicalSanCert uses "auto.example.pro"; plain cert uses "example.com".
        lenient().when(udcRepository.findById(any())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            String domain = (canonicalUdcId != null && canonicalUdcId.equals(id))
                    ? "auto.example.pro"
                    : "example.com";
            return Optional.of(UserDomainCertEntity.builder()
                    .id(id)
                    .organizationId(ORGANIZATION_ID)
                    .domain(domain)
                    .build());
        });
    }

    // ================================================================== //
    //  Drain-loop contract: tryProcessOneEligible returns false when empty
    // ================================================================== //

    @Test
    void tryProcessOneEligible_emptyQueue_returnsFalse() {
        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.empty());

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isFalse();
        verify(publisher, never()).publishRenewal(any());
        verify(certificateRepository, never()).updateStatus(any(), any());
    }

    // ================================================================== //
    //  Per-cert eligibility checks (validator, CA flag, missing cert)
    // ================================================================== //

    @Test
    void tryProcessOneEligible_certStatusNotEligible_marksScheduleFailed() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("ACTIVE");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(false);

        boolean processed = service.tryProcessOneEligible();

        // Row was claimed (so drain loop continues), but cert was skipped — schedule is marked
        // FAILED to prevent re-claim on every iteration.
        assertThat(processed).isTrue();
        ArgumentCaptor<RenewalScheduleEntity> captor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(captor.capture());
        assertThat(captor.getValue().getLastRenewalStatus()).isEqualTo("FAILED");

        verify(publisher, never()).publishRenewal(any());
        verify(certificateRepository, never()).updateStatus(any(), any());
    }

    @Test
    void tryProcessOneEligible_certNotFound_marksScheduleFailed() {
        RenewalScheduleEntity schedule = schedule();

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        ArgumentCaptor<RenewalScheduleEntity> captor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(captor.capture());
        assertThat(captor.getValue().getLastRenewalStatus()).isEqualTo("FAILED");

        verify(publisher, never()).publishRenewal(any());
    }

    // ================================================================== //
    //  Standard renewal happy + failure paths
    // ================================================================== //

    @Test
    void tryProcessOneEligible_publishFailure_revertsToPreviousStatus() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("FAILED");
        OffsetDateTime beforeAttempt = OffsetDateTime.now(ZoneOffset.UTC);

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfig();
        doThrow(new RuntimeException("publish refused", new IllegalArgumentException("message rejected before sending")))
                .when(publisher).publishRenewal(any());

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        verify(certificateRepository).updateStatus(XREF, "RENEWING");
        // Revert path: status reverted to previous (FAILED) after publish failure
        verify(certificateRepository).updateStatus(XREF, "FAILED");
        assertThat(schedule.getConsecutiveFailures()).isEqualTo(1);

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(certEventRepository, times(2)).save(eventCaptor.capture());
        assertThat(eventCaptor.getAllValues())
                .extracting(CertificateEventEntity::getEventType)
                .containsExactlyInAnyOrder("RENEWAL_REQUESTED", "RENEWAL_PUBLISH_FAILED");
        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(schedule.getNextAttemptAt()).isAfter(beforeAttempt);
    }

    @Test
    void tryProcessOneEligible_aPublishThatMayHaveBeenSent_leavesTheAttemptInFlight() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("ACTIVE");
        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfig();
        doThrow(new IllegalStateException("send timed out")).when(publisher).publishRenewal(any());

        assertThat(service.tryProcessOneEligible()).isTrue();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("IN_PROGRESS");
        assertThat(schedule.getConsecutiveFailures()).isZero();
        verify(certificateRepository).updateStatus(XREF, "RENEWING");
        verify(certificateRepository, never()).updateStatus(XREF, "ACTIVE");
        ArgumentCaptor<CertificateEventEntity> events = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(certEventRepository).save(events.capture());
        assertThat(events.getValue().getEventType()).isEqualTo("RENEWAL_REQUESTED");
    }

    @Test
    void tryProcessOneDueRetry_claimsFromTheRetryQueueAndRenews() {
        RenewalScheduleEntity schedule = schedule();
        schedule.setLastRenewalStatus("FAILED");
        schedule.setConsecutiveFailures(2);
        CertificateEntity cert = cert("ACTIVE");
        when(renewalScheduleRepository.claimOneDueRetry(any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfig();

        assertThat(service.tryProcessOneDueRetry()).isTrue();

        verify(publisher).publishRenewal(any());
        verify(renewalScheduleRepository, never()).claimOneEligible(any(), any());
    }

    @Test
    void tryProcessOneDueRetry_nothingDue_endsTheDrain() {
        assertThat(service.tryProcessOneDueRetry()).isFalse();
    }

    @Test
    void tryProcessOneEligible_missingPrimaryDnsMapping_parksFailureUntilConfigurationChanges() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("ACTIVE");
        DomainCredentialConfigEntity configWithoutPrimaryDomain = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .dnsConfig(Map.of("unrelated.example", "dns-cred-xref"))
                .deploymentTargets(List.of())
                .build();

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        when(domainCredConfigRepository.findById(CONFIG_ID))
                .thenReturn(Optional.of(configWithoutPrimaryDomain));

        service.tryProcessOneEligible();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(schedule.getNextAttemptAt()).isNull();
        verify(publisher, never()).publishRenewal(any());
    }

    @Test
    void tryProcessOneEligible_success_eventUsesActualPreviousStatus() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("EXPIRED");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfig();

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(certEventRepository).save(eventCaptor.capture());

        CertificateEventEntity event = eventCaptor.getValue();
        assertThat(event.getEventType()).isEqualTo("RENEWAL_REQUESTED");
        assertThat(event.getFromStatus()).isEqualTo("EXPIRED");
        assertThat(event.getToStatus()).isEqualTo("RENEWING");

        verify(certificateRepository).updateStatus(eq(XREF), eq("RENEWING"));
    }

    @Test
    void tryProcessOneEligible_canonicalMultiRootSanCert_publishesStoredSanDomainPatterns() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = canonicalSanCert("ACTIVE");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfigForCanonical();

        service.tryProcessOneEligible();

        ArgumentCaptor<CertRenewalCommand> cmdCaptor = ArgumentCaptor.forClass(CertRenewalCommand.class);
        verify(publisher).publishRenewal(cmdCaptor.capture());
        CertRenewalCommand cmd = cmdCaptor.getValue();

        assertThat(cmd.getDomain()).isEqualTo("auto.example.pro");
        assertThat(cmd.getWildcard()).isTrue();

        assertThat(cmd.getSanDomainEntries()).hasSize(2);
        List<List<String>> allPatterns = cmd.getSanDomainEntries().stream()
                .map(CertRenewalCommand.SanDomainEntry::getPatterns)
                .toList();
        assertThat(allPatterns).containsExactlyInAnyOrder(
                List.of("example.tech", "*.example.tech"),
                List.of("example.pro", "*.example.pro"));
    }

    @Test
    void tryProcessOneEligible_globalSignDisabledForOrg_doesNotRenew() {
        CertificateEntity cert = cert("ACTIVE");
        cert.setCaProvider(CaProvider.GLOBALSIGN);
        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule()));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(featureFlagService.isEnabled(com.certmanagement.constants.FeatureFlags.CA_GLOBALSIGN, ORGANIZATION_ID))
                .thenReturn(false);

        assertThat(service.tryProcessOneEligible()).isTrue();

        verify(publisher, never()).publishRenewal(any());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(CaProvider.class)
    void tryProcessOneEligible_renewalOffForOrg_holdsScheduleForEveryCa(CaProvider caProvider) {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("ACTIVE");
        cert.setCaProvider(caProvider);
        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(featureFlagResolver.automaticWorkBlockerUncached(FeatureFlags.CERTIFICATE_RENEWAL, ORGANIZATION_ID))
                .thenReturn(Optional.of(FeatureFlags.CERTIFICATE_RENEWAL));

        assertThat(service.tryProcessOneEligible()).isTrue();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");
        assertThat(schedule.getNextAttemptAt()).isAfter(OffsetDateTime.now(ZoneOffset.UTC));
        assertThat(schedule.getEnabled()).isTrue();
        verify(renewalScheduleRepository).save(schedule);
        verify(publisher, never()).publishRenewal(any());
        verify(certificateRepository, never()).updateStatus(any(), any());
        verify(certificateAudit).autoRenewalSkippedByJob(cert,
                com.certmanagement.constants.FeatureFlags.CERTIFICATE_RENEWAL);
    }

    @Test
    void tryProcessOneEligible_dnsCredentialsOff_holdsUnderTheirKey() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("ACTIVE");
        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(featureFlagResolver.automaticWorkBlockerUncached(FeatureFlags.CERTIFICATE_RENEWAL, ORGANIZATION_ID))
                .thenReturn(Optional.of(FeatureFlags.DNS_CREDENTIALS));

        assertThat(service.tryProcessOneEligible()).isTrue();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");
        assertThat(schedule.getNextAttemptAt()).isAfter(OffsetDateTime.now(ZoneOffset.UTC));
        verify(publisher, never()).publishRenewal(any());
        verify(certificateAudit).autoRenewalSkippedByJob(cert,
                com.certmanagement.constants.FeatureFlags.DNS_CREDENTIALS);
    }

    @Test
    void tryProcessOneEligible_anExpiredCertPingDnsKey_holdsTheScheduleAndAuditsOnce() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = cert("ACTIVE");
        Instant expiredAt = Instant.parse("2026-10-01T00:00:00Z");
        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(domainCredConfigRepository.findById(CONFIG_ID)).thenReturn(Optional.of(DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID).dnsConfig(Map.of("example.com", "cred-certping", "unused.org", "cred-unused")).build()));
        when(certPingDnsKeys.earliestExpired(eq(ORGANIZATION_ID),
                argThat((Collection<String> xrefs) -> Set.copyOf(xrefs).equals(Set.of("cred-certping"))),
                any())).thenReturn(Optional.of(expiredAt));

        assertThat(service.tryProcessOneEligible()).isTrue();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("DNS_KEY_EXPIRED_HOLD");
        assertThat(schedule.getNextAttemptAt()).isBetween(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(59),
                OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(61));
        assertThat(schedule.getEnabled()).isTrue();
        verify(publisher, never()).publishRenewal(any());
        verify(certificateRepository, never()).updateStatus(any(), any());
        verify(certificateAudit).autoRenewalHeldByExpiredDnsKey(cert, expiredAt);

        assertThat(service.tryProcessOneEligible()).as("checked again while still held").isTrue();
        verify(certificateAudit, times(1)).autoRenewalHeldByExpiredDnsKey(any(), any());
    }

    @Test
    void tryProcessOneEligible_renewalOffForOrg_holdsAkamaiSpecialToo() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = akamaiCert("ACTIVE");
        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(featureFlagResolver.automaticWorkBlockerUncached(FeatureFlags.CERTIFICATE_RENEWAL, ORGANIZATION_ID))
                .thenReturn(Optional.of(FeatureFlags.CERTIFICATE_RENEWAL));

        assertThat(service.tryProcessOneEligible()).isTrue();

        assertThat(schedule.getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");
        verify(akamaiSpecialIssuanceService, never()).triggerAkamaiSpecialIssuance(any(), any(), any(), any(), any());
    }

    // ================================================================== //
    //  Stuck IN_PROGRESS recovery
    // ================================================================== //

    @Test
    void tryProcessOneEligible_stuckInProgress_cleansUpAndRetries() {
        // Schedule the claim query returned has status=IN_PROGRESS (came back via the
        // stuck-timeout WHERE-clause branch).
        RenewalScheduleEntity stuckSchedule = schedule();
        stuckSchedule.setLastRenewalStatus("IN_PROGRESS");
        stuckSchedule.setUpdatedAt(OffsetDateTime.now(ZoneOffset.UTC)
                .minus(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON).minusHours(1));

        CertificateEntity sourceCert = cert("RENEWING");
        sourceCert.setValidTo(OffsetDateTime.now(ZoneOffset.UTC).plusDays(5));  // still valid

        // The orphan PENDING draft from the previous attempt
        CertificateEntity orphanDraft = CertificateEntity.builder()
                .certificateXref("cert-orphan-draft")
                .userDomainCertId(sourceCert.getUserDomainCertId())
                .status("PENDING")
                .caProvider(CaProvider.LETS_ENCRYPT)
                .build();

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(stuckSchedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(sourceCert));
        // For the post-cleanup flow, the validator should accept ACTIVE (which is what
        // cleanup reverts the source cert to). We can't easily simulate that here since
        // updateStatus is a mock — we'll just allow any status.
        when(certificateStatusValidator.isEligibleForScheduledRenewal(any(), any())).thenReturn(true);
        // The cleanup finds the orphan draft by UDC + PENDING
        when(certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                        sourceCert.getUserDomainCertId(), "PENDING"))
                .thenReturn(Optional.of(orphanDraft));
        stubCredConfig();

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();

        // Cleanup side effects: orphan draft marked RENEWAL_FAILED, source cert reverted from
        // RENEWING to ACTIVE (validTo is in the future). The retry then INSERTs a new draft
        // — so we expect two saves on certificateRepository: orphan (RENEWAL_FAILED) + new draft.
        ArgumentCaptor<CertificateEntity> draftCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository, times(2)).save(draftCaptor.capture());
        assertThat(draftCaptor.getAllValues())
                .extracting(CertificateEntity::getStatus)
                .contains("RENEWAL_FAILED");
        // The orphan draft (the one marked RENEWAL_FAILED) should carry the recovery error code.
        CertificateEntity orphanWrite = draftCaptor.getAllValues().stream()
                .filter(c -> "RENEWAL_FAILED".equals(c.getStatus()))
                .findFirst().orElseThrow();
        assertThat(orphanWrite.getLastErrorCode()).isEqualTo("RENEWAL_RESPONSE_TIMEOUT");

        verify(certificateRepository).updateStatus(XREF, "ACTIVE");  // revert from RENEWING

        // The retry then proceeds — RENEWING update happens for the new attempt.
        verify(certificateRepository).updateStatus(XREF, "RENEWING");
        verify(publisher).publishRenewal(any());
    }

    @Test
    void tryProcessOneEligible_stuckInProgress_validToPassed_revertsToExpired() {
        RenewalScheduleEntity stuckSchedule = schedule();
        stuckSchedule.setLastRenewalStatus("IN_PROGRESS");
        stuckSchedule.setUpdatedAt(OffsetDateTime.now(ZoneOffset.UTC)
                .minus(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON).minusHours(1));

        CertificateEntity sourceCert = cert("RENEWING");
        sourceCert.setValidTo(OffsetDateTime.now(ZoneOffset.UTC).minusDays(1));  // expired

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(stuckSchedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(sourceCert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(any(), any())).thenReturn(true);
        // No orphan draft on this UDC
        when(certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                        sourceCert.getUserDomainCertId(), "PENDING"))
                .thenReturn(Optional.empty());
        stubCredConfig();

        service.tryProcessOneEligible();

        // Source cert was RENEWING with past validTo → cleanup reverts to EXPIRED
        verify(certificateRepository).updateStatus(XREF, "EXPIRED");
    }

    // ================================================================== //
    //  AKAMAI_CPS special-cert renewal path
    // ================================================================== //

    @Test
    void tryProcessOneEligible_akamaiCpsCert_callsTriggerInsteadOfCertRenewalCommand() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = akamaiCert("ACTIVE");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfigWithAkamaiTarget();

        boolean processed = service.tryProcessOneEligible();

        assertThat(processed).isTrue();
        verify(akamaiSpecialIssuanceService).triggerAkamaiSpecialIssuance(
                eq(ORGANIZATION_ID), eq(cert), eq(schedule), any(), any());
        verify(publisher, never()).publishRenewal(any());
    }

    @Test
    void tryProcessOneEligible_akamaiCpsCert_doesNotMarkCertAsRenewing() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = akamaiCert("ACTIVE");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfigWithAkamaiTarget();

        service.tryProcessOneEligible();

        verify(certificateRepository, never()).updateStatus(any(), any());
    }

    @Test
    void tryProcessOneEligible_akamaiCpsCert_marksScheduleInProgress() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = akamaiCert("ACTIVE");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfigWithAkamaiTarget();

        service.tryProcessOneEligible();

        ArgumentCaptor<RenewalScheduleEntity> captor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(captor.capture());
        assertThat(captor.getValue().getLastRenewalStatus()).isEqualTo("IN_PROGRESS");
    }

    @Test
    void tryProcessOneEligible_akamaiCpsCert_triggerFailure_marksScheduleFailed() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = akamaiCert("ACTIVE");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);
        stubCredConfigWithAkamaiTarget();
        doThrow(new RuntimeException("Akamai API down"))
                .when(akamaiSpecialIssuanceService).triggerAkamaiSpecialIssuance(any(), any(), any(), any(), any());

        service.tryProcessOneEligible();

        ArgumentCaptor<RenewalScheduleEntity> captor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository, times(2)).save(captor.capture());
        assertThat(captor.getAllValues().get(1).getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(captor.getAllValues().get(1).getNextAttemptAt()).isNotNull();
    }

    @Test
    void tryProcessOneEligible_akamaiCpsCert_noAkamaiCredInTargets_marksScheduleFailed() {
        RenewalScheduleEntity schedule = schedule();
        CertificateEntity cert = akamaiCert("ACTIVE");

        when(renewalScheduleRepository.claimOneEligible(any(), any())).thenReturn(Optional.of(schedule));
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(certificateStatusValidator.isEligibleForScheduledRenewal(cert, XREF)).thenReturn(true);

        // credConfig with a non-Akamai deployment target only
        CredentialReferenceEntity nonAkamaiCred = CredentialReferenceEntity.builder()
                .credentialXref("cred-azure-kv")
                .provider("AZURE_KV")
                .secretHandle("kv/deploy/azure")
                .status("ACTIVE")
                .type("DEPLOYMENT")
                .build();
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .dnsConfig(Map.of("example.com", "dns-cred-xref"))
                .deploymentTargets(List.of("cred-azure-kv"))
                .build();
        when(domainCredConfigRepository.findById(CONFIG_ID)).thenReturn(Optional.of(credConfig));
        when(credentialService.getByXref(any(), eq("cred-azure-kv"))).thenReturn(nonAkamaiCred);

        service.tryProcessOneEligible();

        ArgumentCaptor<RenewalScheduleEntity> captor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository, times(2)).save(captor.capture());
        assertThat(captor.getAllValues().get(1).getLastRenewalStatus()).isEqualTo("FAILED");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubCredConfigForCanonical() {
        Map<String, String> dnsConfig = new LinkedHashMap<>();
        dnsConfig.put("example.pro", "cred-example");
        dnsConfig.put("example.tech", "cred-example");

        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .dnsConfig(dnsConfig)
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigRepository.findById(CONFIG_ID)).thenReturn(Optional.of(credConfig));

        CredentialReferenceEntity exampleCred = CredentialReferenceEntity.builder()
                .credentialXref("cred-example")
                .provider("CLOUDFLARE")
                .secretHandle("kv/dns/example")
                .status("ACTIVE")
                .type("DNS")
                .build();
        when(credentialService.getByXref(any(), eq("cred-example"))).thenReturn(exampleCred);
    }

    private CertificateEntity canonicalSanCert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(++idCounter)
                .organizationId(ORGANIZATION_ID)
                .domain("auto.example.pro")
                .build();
        canonicalUdcId = udc.getId();
        return CertificateEntity.builder()
                .certificateXref(XREF)
                .userDomainCertId(udc.getId())
                .userDomainCert(udc)
                .wildcard(true)
                .san(true)
                .sanDomains(new String[]{
                        "*.auto.example.pro",
                        "example.pro",
                        "*.example.pro",
                        "example.tech",
                        "*.example.tech"})
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .status(status)
                .build();
    }

    private void stubCredConfig() {
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .dnsConfig(Map.of("example.com", "dns-cred-xref"))
                .deploymentTargets(List.of())
                .build();
        when(domainCredConfigRepository.findById(CONFIG_ID)).thenReturn(Optional.of(credConfig));

        CredentialReferenceEntity dnsCred = CredentialReferenceEntity.builder()
                .credentialXref("dns-cred-xref")
                .provider("CLOUDFLARE")
                .secretHandle("https://kv.vault.azure.net/secrets/dns")
                .status("ACTIVE")
                .type("DNS")
                .build();
        when(credentialService.getByXref(any(), eq("dns-cred-xref"))).thenReturn(dnsCred);
    }

    private RenewalScheduleEntity schedule() {
        return RenewalScheduleEntity.builder()
                .certificateXref(XREF)
                .domainCredentialConfigId(CONFIG_ID)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .renewalEligibleAt(OffsetDateTime.now(ZoneOffset.UTC).minusDays(1))
                .validTo(OffsetDateTime.now(ZoneOffset.UTC).plusDays(10))
                .enabled(true)
                .build();
    }

    private CertificateEntity cert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(++idCounter)
                .organizationId(ORGANIZATION_ID)
                .domain("example.com")
                .build();
        return CertificateEntity.builder()
                .certificateXref(XREF)
                .userDomainCertId(udc.getId())
                .userDomainCert(udc)
                .wildcard(false)
                .san(false)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .status(status)
                .build();
    }

    // ── Akamai helpers ────────────────────────────────────────────────────────

    private CertificateEntity akamaiCert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(++idCounter)
                .organizationId(ORGANIZATION_ID)
                .domain("example.com")
                .build();
        return CertificateEntity.builder()
                .certificateXref(XREF)
                .userDomainCertId(udc.getId())
                .userDomainCert(udc)
                .wildcard(false)
                .san(false)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .status(status)
                .specialCertificateType("AKAMAI_CPS")
                .build();
    }

    private void stubCredConfigWithAkamaiTarget() {
        CredentialReferenceEntity akamaiCred = CredentialReferenceEntity.builder()
                .credentialXref("cred-akamai")
                .provider("AKAMAI_CPS")
                .secretHandle("kv/deploy/akamai")
                .status("ACTIVE")
                .type("DEPLOYMENT")
                .build();
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .dnsConfig(Map.of("example.com", "dns-cred-xref"))
                .deploymentTargets(List.of("cred-akamai"))
                .build();
        when(domainCredConfigRepository.findById(CONFIG_ID)).thenReturn(Optional.of(credConfig));
        when(credentialService.getByXref(any(), eq("cred-akamai"))).thenReturn(akamaiCred);
    }
}
