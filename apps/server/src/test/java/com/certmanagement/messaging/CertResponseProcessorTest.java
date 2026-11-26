// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.CertManualIssuanceStateEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.messaging.model.CertDeploymentResponse;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import com.certmanagement.messaging.model.CertManualTxtResponse;
import com.certmanagement.messaging.model.CertRevocationResponse;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.entity.AlertEntity;
import com.certmanagement.enums.AlertTypeEnum;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateCryptoMetadataRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.AlertService;
import com.certmanagement.service.agent.AgentHealthService;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.discovery.DiscoveryService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertResponseProcessorTest {

    @Mock private CertificateRepository                certificateRepository;
    @Mock private CertificateCryptoMetadataRepository  cryptoMetadataRepository;
    @Mock private CertificateEventRepository           eventRepository;
    @Mock private RenewalScheduleRepository            renewalScheduleRepository;
    @Mock private DomainCredentialConfigRepository     domainCredConfigRepository;
    @Mock private CertManualIssuanceStateRepository    manualIssuanceStateRepository;
    @Mock private CertIssuanceService certIssuanceService;
    @Mock private NotificationPublisher                notificationPublisher;
    @Mock private AlertRepository                      alertRepository;
    @Mock private DeploymentExecutionService           deploymentExecutionService;
    @Mock private com.certmanagement.service.lifecycle.FeatureLifecycleLock featureLifecycleLock;
    @Mock private com.certmanagement.repository.DeploymentRepository deploymentRepository;
    private final com.certmanagement.service.FeatureFlagResolver featureFlagResolver =
            com.certmanagement.testing.FeatureFlagResolvers.allEnabled();
    @Mock private CertDeploymentConfigService          certDeploymentConfigService;
    @Mock private CredentialReferenceRepository        credentialReferenceRepository;
    @Mock private AgentHealthService                   agentHealthService;
    @Mock private AgentDeepHealthCheckService          agentDeepHealthCheckService;
    @Mock private DiscoveryService                     discoveryService;
    @Mock private com.certmanagement.iot.messaging.IotIdentitySyncResponseHandler iotIdentitySyncResponseHandler;
    @Mock private com.certmanagement.iot.service.IotDeviceSourceHealthService iotDeviceSourceHealthService;
    @Mock private com.certmanagement.iot.profile.CertificateProfileResponseHandler certificateProfileResponseHandler;

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private CertResponseProcessor processor;
    private long certIdCounter = 100;

    private static final String XREF               = "cert-abc123";
    private static final String ORGANIZATION_ID          = "organization-";
    private static final Long   CERT_ORGANIZATION_   = 1L;
    private static final String CERT_ORGANIZATION_ID_STR = CERT_ORGANIZATION_.toString();
    private static final Long   UDC_ID             = 2L;
    private static final Long   CONFIG_ID          = 3L;
    private static final String REQ_ID             = "req-";
    private static final String CORR_ID            = "corr-";
    private static final String VALID_FROM         = "2026-03-14T00:00:00Z";
    private static final String VALID_TO           = "2026-06-12T00:00:00Z";
    private static final String RENEWED_XREF       = "cert-renewed-123";

    @BeforeEach
    void setUp() {
        AlertService alertService = new AlertService(alertRepository, mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class));
        processor = new CertResponseProcessor(
                certificateRepository,
                cryptoMetadataRepository,
                eventRepository,
                renewalScheduleRepository,
                domainCredConfigRepository,
                manualIssuanceStateRepository,
                certIssuanceService,
                notificationPublisher,
                alertService,
                objectMapper,
                deploymentExecutionService,
                certDeploymentConfigService,
                credentialReferenceRepository,
                agentHealthService,
                agentDeepHealthCheckService,
                discoveryService,
                iotIdentitySyncResponseHandler,
                iotDeviceSourceHealthService,
                certificateProfileResponseHandler,
                org.mockito.Mockito.mock(com.certmanagement.iot.certificate.IotCertificateIngestionService.class),
                org.mockito.Mockito.mock(com.certmanagement.iot.certificate.IotDeviceNudgeResultService.class),
                org.mockito.Mockito.mock(com.certmanagement.iot.cahealth.IotCaHealthService.class),
                org.mockito.Mockito.mock(com.certmanagement.iot.revocation.IotRevocationResultService.class),
                org.mockito.Mockito.mock(com.certmanagement.iot.revocation.IotIntuneRevocationWorkflow.class),
                com.certmanagement.testing.Transactions.inline(), featureLifecycleLock, featureFlagResolver,
                deploymentRepository, org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
        lenient().when(deploymentExecutionService.planAutoDeploy(any(), anyBoolean()))
                .thenReturn(com.certmanagement.service.deployment.DeploymentExecutionService.AutoDeployOutcome.DISPATCHED);

            lenient().when(certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                    anyLong(),
                    eq(CertificateStatus.ACTIVE.name())))
                .thenReturn(Optional.empty());
    }

    // ------------------------------------------------------------------ //
    //  Helpers
    // ------------------------------------------------------------------ //

    private UserDomainCertEntity buildUdc() {
        return UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(CERT_ORGANIZATION_)
                .domain("example.com")
                .build();
    }

    private CertificateEntity buildCert(String status) {
        UserDomainCertEntity udc = buildUdc();
        return CertificateEntity.builder()
                .id(++certIdCounter)
                .certificateXref(XREF)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .build();
    }

    private CertificateEntity buildRenewedDraft(String xref) {
        UserDomainCertEntity udc = buildUdc();
        return CertificateEntity.builder()
                .id(++certIdCounter)
                .certificateXref(xref)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status("PENDING")
                .build();
    }

    /** Cert with certSecretHandle set — required for recovery schedule creation. */
    private CertificateEntity buildCertWithKvPath(String status) {
        CertificateEntity cert = buildCert(status);
        cert.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");
        return cert;
    }

    private RenewalScheduleEntity buildSchedule() {
        return RenewalScheduleEntity.builder()
                .certificateXref(XREF)
                .domainCredentialConfigId(CONFIG_ID)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .caProvider(CaProvider.LETS_ENCRYPT)
                .validTo(OffsetDateTime.now().plusMonths(3))
                .renewalEligibleAt(OffsetDateTime.now().plusMonths(2))
                .renewalWindowDays(30)
                .enabled(false)
                .build();
    }

    private DomainCredentialConfigEntity buildCredConfig() {
        return DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .userDomainCertId(UDC_ID)
                .dnsConfig(Map.of("example.com", "cred-dns"))
                .deploymentTargets(List.of())
                .build();
    }

    private boolean process(String messageType, Object payload) throws Exception {
        String body = objectMapper.writeValueAsString(payload);
        AtomicBoolean completed = new AtomicBoolean(false);
        processor.process(messageType, body, verifiedFor(messageType), () -> completed.set(true), () -> {});
        return completed.get();
    }

    private boolean processRaw(String messageType, String rawBody) {
        AtomicBoolean completed = new AtomicBoolean(false);
        processor.process(messageType, rawBody, verifiedFor(messageType), () -> completed.set(true), () -> {});
        return completed.get();
    }

    private boolean processAndExpectAbandon(String messageType, String rawBody) {
        AtomicBoolean abandoned = new AtomicBoolean(false);
        processor.process(messageType, rawBody, verifiedFor(messageType), () -> {}, () -> abandoned.set(true));
        return abandoned.get();
    }

    // ------------------------------------------------------------------ //
    //  Flow 1: Cert Issuance (CERT_ISSUANCE_RESPONSE, status=ISSUED)
    // ------------------------------------------------------------------ //

    @Test
    void issuanceSuccess_updatesCertToActive() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        boolean completed = process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));
        assertThat(completed).isTrue();

        ArgumentCaptor<CertificateEntity> captor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(captor.capture());
        CertificateEntity saved = captor.getValue();

        assertThat(saved.getStatus()).isEqualTo("ACTIVE");
        assertThat(saved.getIssuer()).isEqualTo("Let's Encrypt");
        assertThat(saved.getSerialNumber()).isEqualTo("04:AB:CD");
        assertThat(saved.getAcmeAccountHandle()).isEqualTo("https://kv.vault.azure.net/secrets/acme");
        assertThat(saved.getValidFrom()).isNotNull();
        assertThat(saved.getValidTo()).isNotNull();
        assertThat(saved.getLastErrorCode()).isNull();
        assertThat(saved.getLastErrorMessage()).isNull();
        assertThat(saved.getLastErrorAt()).isNull();
    }

    @Test
    void issuanceSuccess_withPriorActive_demotesOldActiveBeforePromotingNew() throws Exception {
        CertificateEntity pending = buildCert("PENDING");
        CertificateEntity priorActive = buildCert("ACTIVE");
        priorActive.setCertificateXref("cert-old-active");

        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(pending));
        when(certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "ACTIVE"))
                .thenReturn(Optional.of(priorActive));
        when(renewalScheduleRepository.findByCertificateXref("cert-old-active"))
                .thenReturn(Optional.of(RenewalScheduleEntity.builder()
                        .certificateXref("cert-old-active")
                        .enabled(true)
                        .build()));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository, atLeast(2)).save(certCaptor.capture());
        assertThat(certCaptor.getAllValues()).anySatisfy(saved -> {
            assertThat(saved.getCertificateXref()).isEqualTo("cert-old-active");
            assertThat(saved.getStatus()).isEqualTo("RENEW_SUCCESS");
        });
        assertThat(certCaptor.getAllValues()).anySatisfy(saved -> {
            assertThat(saved.getCertificateXref()).isEqualTo(XREF);
            assertThat(saved.getStatus()).isEqualTo("ACTIVE");
        });

        ArgumentCaptor<RenewalScheduleEntity> rsCaptor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(rsCaptor.capture());
        assertThat(rsCaptor.getValue().getCertificateXref()).isEqualTo("cert-old-active");
        assertThat(rsCaptor.getValue().getEnabled()).isFalse();

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository, atLeast(2)).save(eventCaptor.capture());
        assertThat(eventCaptor.getAllValues())
                .extracting(CertificateEventEntity::getEventType)
                .contains("STATUS_CHANGED", "ISSUANCE_SUCCESS");
    }

    @Test
    void issuanceSuccess_callsDispatchForCert() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildSchedule()));

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));

        verify(deploymentExecutionService).dispatchForCert(any(), eq("https://kv.vault.azure.net/secrets/cert"), eq(ORGANIZATION_ID), eq("AUTO_POST_ISSUANCE"));
    }

    @Test
    void issuanceSuccess_enablesRenewalScheduleAndMirrorsAcmePath() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildSchedule()));

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));

        ArgumentCaptor<RenewalScheduleEntity> captor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(captor.capture());
        RenewalScheduleEntity saved = captor.getValue();

        assertThat(saved.getEnabled()).isTrue();
        assertThat(saved.getLastRenewalStatus()).isNull();
        assertThat(saved.getAcmeAccountHandle()).isEqualTo("https://kv.vault.azure.net/secrets/acme");
        assertThat(saved.getValidTo()).isNotNull();
        assertThat(saved.getRenewalEligibleAt()).isBefore(saved.getValidTo());
    }

    @Test
    void issuanceSuccess_publishesNotificationWithAllRequiredFields() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher).publish(
                eq("CERT_ISSUANCE_SUCCESS"), eq(ORGANIZATION_ID), eq(XREF), captor.capture());

        Map<String, Object> fields = captor.getValue();
        assertThat(fields).containsEntry("domain", "example.com");
        assertThat(fields).containsEntry("validFrom", VALID_FROM);
        assertThat(fields).containsEntry("validTo", VALID_TO);
    }

    @Test
    void issuanceSuccess_insertsIssuanceSuccessEvent() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));

        ArgumentCaptor<CertificateEventEntity> captor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(captor.capture());

        assertThat(captor.getValue().getEventType()).isEqualTo("ISSUANCE_SUCCESS");
        assertThat(captor.getValue().getFromStatus()).isEqualTo("PENDING");
        assertThat(captor.getValue().getToStatus()).isEqualTo("ACTIVE");
        assertThat(captor.getValue().getSource()).isEqualTo("certping-agent");
        assertThat(captor.getValue().getRequestId()).isEqualTo(REQ_ID);
    }

    @Test
    void issuanceSuccess_unknownXref_skipsAllSideEffectsButCompletes() throws Exception {
        when(certificateRepository.findByCertificateXref(any())).thenReturn(Optional.empty());

        CertIssuanceResponse response = issuanceResponse("ISSUED");
        response.setCertificateXref("unknown-xref");

        boolean completed = process("CERT_ISSUANCE_RESPONSE", response);

        verify(certificateRepository, never()).save(any());
        verify(renewalScheduleRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
        assertThat(completed).isTrue();
    }

    @Test
    void issuanceSuccess_cancelledManual_ignoresStaleResponse() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF))
                .thenReturn(Optional.of(buildCert("CANCELLED_MANUAL")));

        boolean completed = process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));

        assertThat(completed).isTrue();
        verify(manualIssuanceStateRepository).deleteByCertXref(XREF);
        verify(certificateRepository, never()).save(any());
        verify(renewalScheduleRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(eq("CERT_ISSUANCE_SUCCESS"), any(), any(), any());
    }

    @Test
    void issuanceSuccess_missingSchedule_createsRecoveryScheduleViaCredConfig() throws Exception {
        CertificateEntity cert = buildCertWithKvPath("PENDING");
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        // No schedule → fallback via userDomainCertId
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID))
                .thenReturn(Optional.of(buildCredConfig()));

        boolean completed = process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));
        assertThat(completed).isTrue();

        ArgumentCaptor<RenewalScheduleEntity> captor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(captor.capture());
        RenewalScheduleEntity recovery = captor.getValue();

        assertThat(recovery.getEnabled()).isTrue();
        assertThat(recovery.getCertificateXref()).isEqualTo(XREF);
        assertThat(recovery.getDomainCredentialConfigId()).isEqualTo(CONFIG_ID);
        assertThat(recovery.getCertSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/cert");
        assertThat(recovery.getValidTo()).isNotNull();
        assertThat(recovery.getRenewalEligibleAt()).isBefore(recovery.getValidTo());
    }

    @Test
    void notificationFailure_doesNotCauseMessageAbandonment() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        doThrow(new RuntimeException("notification queue down"))
                .when(notificationPublisher).publish(any(), any(), any(), any());

        AtomicBoolean completed = new AtomicBoolean(false);
        AtomicBoolean abandoned = new AtomicBoolean(false);
        String body = objectMapper.writeValueAsString(issuanceResponse("ISSUED"));

        processor.process("CERT_ISSUANCE_RESPONSE", body, verifiedFor("CERT_ISSUANCE_RESPONSE"),
                () -> completed.set(true), () -> abandoned.set(true));

        assertThat(completed.get()).isTrue();
        assertThat(abandoned.get()).isFalse();
        verify(certificateRepository).save(any());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.NullAndEmptySource
    @org.junit.jupiter.params.provider.ValueSource(strings = {"   ", "2026-13-45T00:00:00Z", "2026-06-12T00:00:00",
            "not a date"})
    void issuanceWithoutAReadableExpiry_isRecordedAsAFailureNeverActive(String validTo) throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        CertIssuanceResponse response = issuanceResponse("ISSUED");
        response.setValidTo(validTo);

        assertThat(process("CERT_ISSUANCE_RESPONSE", response)).isTrue();

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("FAILED");
        assertThat(certCaptor.getValue().getValidTo()).isNull();
        assertThat(certCaptor.getValue().getLastErrorCode()).isEqualTo("ISSUED_WITHOUT_EXPIRY");
        verify(notificationPublisher).publish(eq("CERT_ISSUANCE_FAILED"), eq(ORGANIZATION_ID), eq(XREF), any());
        verify(renewalScheduleRepository, never()).save(any());
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "2026-06-12T00:00:00Z,      2026-06-12T00:00:00Z",
            "2026-06-12T05:30:00+05:30, 2026-06-12T00:00:00Z",
            "2026-06-12T00:00:00.123Z,  2026-06-12T00:00:00.123Z"})
    void issuanceStoresTheExpiryExactly(String sent, String expectedInstant) throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        CertIssuanceResponse response = issuanceResponse("ISSUED");
        response.setValidTo(sent);

        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("ACTIVE");
        assertThat(certCaptor.getValue().getValidTo().toInstant()).isEqualTo(java.time.Instant.parse(expectedInstant));
    }

    @Test
    void renewalWithoutAReadableExpiry_failsTheDraftAndRestoresThePreviousCertificate() throws Exception {
        CertificateEntity draft = buildRenewedDraft(RENEWED_XREF);
        CertificateEntity previous = buildCert("RENEWING");
        previous.setValidTo(java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).plusDays(20));
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(draft));
        when(certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
                .thenReturn(Optional.of(previous));
        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        response.setValidTo(null);

        assertThat(process("CERT_ISSUANCE_RESPONSE", response)).isTrue();

        assertThat(draft.getStatus()).isEqualTo("RENEWAL_FAILED");
        assertThat(draft.getLastErrorCode()).isEqualTo("ISSUED_WITHOUT_EXPIRY");
        assertThat(previous.getStatus()).isEqualTo("ACTIVE");
    }

    // ------------------------------------------------------------------ //
    //  Flow 2: Cert Renewal (CERT_ISSUANCE_RESPONSE, status=RENEWED)
    // ------------------------------------------------------------------ //

    @Test
    void renewalSuccess_updatesCertAndRecalculatesSchedule() throws Exception {
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(buildRenewedDraft(RENEWED_XREF)));
        when(certificateRepository
            .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
            .thenReturn(Optional.of(buildCert("RENEWING")));

        RenewalScheduleEntity schedule = buildSchedule();
        schedule.setEnabled(true);
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(schedule));

        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        response.setValidFrom("2026-06-12T00:00:00Z");
        response.setValidTo("2026-09-10T00:00:00Z");

        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository, atLeast(2)).save(certCaptor.capture());

        CertificateEntity previousSaved = certCaptor.getAllValues().stream()
            .filter(c -> XREF.equals(c.getCertificateXref()))
            .findFirst()
            .orElseThrow();
        CertificateEntity renewedSaved = certCaptor.getAllValues().stream()
            .filter(c -> !XREF.equals(c.getCertificateXref()))
            .findFirst()
            .orElseThrow();

        assertThat(previousSaved.getStatus()).isEqualTo("RENEW_SUCCESS");
        assertThat(renewedSaved.getStatus()).isEqualTo("ACTIVE");
        assertThat(renewedSaved.getCertificateXref()).isNotEqualTo(XREF);

        ArgumentCaptor<RenewalScheduleEntity> rsCaptor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(rsCaptor.capture());
        RenewalScheduleEntity saved = rsCaptor.getValue();

        assertThat(saved.getCertificateXref()).isEqualTo(renewedSaved.getCertificateXref());
        assertThat(saved.getLastRenewalStatus()).isEqualTo("SUCCESS");
        assertThat(saved.getLastRenewalAt()).isNotNull();
        assertThat(saved.getNextAttemptAt()).isNull();
        assertThat(saved.getValidTo()).isNotNull();
        assertThat(saved.getRenewalEligibleAt()).isBefore(saved.getValidTo());
    }

    @Test
    void renewalSuccess_callsDispatchForCert() throws Exception {
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(buildRenewedDraft(RENEWED_XREF)));
        when(certificateRepository
            .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
            .thenReturn(Optional.of(buildCert("RENEWING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildSchedule()));

        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(deploymentExecutionService).dispatchForCert(certCaptor.capture(), any(), eq(ORGANIZATION_ID), eq("AUTO_POST_RENEWAL"));
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("ACTIVE");
        assertThat(certCaptor.getValue().getCertificateXref()).isNotEqualTo(XREF);
    }

    @Test
    void renewalSuccess_deploymentOff_recordsSkipAndTellsTheCustomer() throws Exception {
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(buildRenewedDraft(RENEWED_XREF)));
        CertificateEntity previous = buildCert("RENEWING");
        OffsetDateTime previousValidTo = OffsetDateTime.parse("2026-11-01T00:00:00Z");
        previous.setValidTo(previousValidTo);
        when(certificateRepository
            .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
            .thenReturn(Optional.of(previous));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildSchedule()));
        when(featureFlagResolver.resolveUncached(eq("CERTIFICATE_DEPLOYMENT"), any())).thenReturn(false);
        when(deploymentExecutionService.planAutoDeploy(any(), eq(false)))
                .thenReturn(com.certmanagement.service.deployment.DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF);

        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<com.certmanagement.entity.CertificateEventEntity> events =
                ArgumentCaptor.forClass(com.certmanagement.entity.CertificateEventEntity.class);
        verify(eventRepository, atLeast(2)).save(events.capture());
        assertThat(events.getAllValues())
                .extracting(com.certmanagement.entity.CertificateEventEntity::getEventType)
                .contains("AUTO_DEPLOY_SKIPPED_FEATURE_OFF");
        org.mockito.InOrder order = org.mockito.Mockito.inOrder(notificationPublisher);
        order.verify(notificationPublisher).publish(eq("CERT_RENEWAL_SUCCESS"), any(), eq(RENEWED_XREF), any());
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        order.verify(notificationPublisher).publish(eq(CertResponseProcessor.CERT_RENEWED_NOT_DEPLOYED), any(),
                eq(RENEWED_XREF), fields.capture());
        assertThat(fields.getValue())
                .containsEntry("requestId", REQ_ID + ":not-deployed")
                .containsEntry("previousCertificateXref", XREF);
        assertThat(OffsetDateTime.parse((String) fields.getValue().get("previousValidTo")))
                .isEqualTo(previousValidTo);
        verify(deploymentExecutionService, never()).dispatchForCert(any(), any(), any(), any());
    }

    @Test
    void renewalSuccess_deploymentSwitchedOffAfterCommit_recordsSkipAndTellsTheCustomer() throws Exception {
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(buildRenewedDraft(RENEWED_XREF)));
        when(certificateRepository
            .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
            .thenReturn(Optional.of(buildCert("RENEWING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildSchedule()));
        when(deploymentExecutionService.dispatchForCert(any(), any(), any(), eq("AUTO_POST_RENEWAL")))
                .thenReturn(com.certmanagement.service.deployment.DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF);

        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<CertificateEventEntity> events = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository, atLeast(2)).save(events.capture());
        assertThat(events.getAllValues()).extracting(CertificateEventEntity::getEventType)
                .contains("AUTO_DEPLOY_SKIPPED_FEATURE_OFF");
        verify(notificationPublisher).publish(eq(CertResponseProcessor.CERT_RENEWED_NOT_DEPLOYED), any(),
                eq(RENEWED_XREF), any());
    }

    @Test
    void renewedNotDeployedRequestId_isStablePerResponse_andFallsBackWhenTheResponseHasNoIds() {
        CertIssuanceResponse response = issuanceResponse("RENEWED");
        assertThat(CertResponseProcessor.notDeployedRequestId(response, RENEWED_XREF))
                .isEqualTo(CertResponseProcessor.notDeployedRequestId(response, RENEWED_XREF))
                .isEqualTo(REQ_ID + ":not-deployed");

        response.setRequestId(null);
        assertThat(CertResponseProcessor.notDeployedRequestId(response, RENEWED_XREF)).isEqualTo(CORR_ID + ":not-deployed");
        response.setCorrelationId(" ");
        assertThat(CertResponseProcessor.notDeployedRequestId(response, RENEWED_XREF))
                .isEqualTo(RENEWED_XREF + ":not-deployed");
    }

    @Test
    void renewalSuccess_publishesRenewalSuccessWithValidFrom() throws Exception {
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(buildRenewedDraft(RENEWED_XREF)));
        when(certificateRepository
            .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
            .thenReturn(Optional.of(buildCert("RENEWING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        response.setValidFrom("2026-06-12T00:00:00Z");
        response.setValidTo("2026-09-10T00:00:00Z");

        process("CERT_ISSUANCE_RESPONSE", response);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        ArgumentCaptor<String> xrefCaptor = ArgumentCaptor.forClass(String.class);
        verify(notificationPublisher).publish(
                eq("CERT_RENEWAL_SUCCESS"), eq(ORGANIZATION_ID), xrefCaptor.capture(), captor.capture());

        assertThat(xrefCaptor.getValue()).isNotEqualTo(XREF);
        Map<String, Object> fields = captor.getValue();
        assertThat(fields).containsEntry("validFrom", "2026-06-12T00:00:00Z");
        assertThat(fields).containsEntry("validTo", "2026-09-10T00:00:00Z");
        assertThat(fields).containsKey("domain");
        assertThat(fields).containsEntry("previousCertificateXref", XREF);
    }

    @Test
    void renewalSuccess_insertsRenewalSuccessEvent() throws Exception {
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(buildRenewedDraft(RENEWED_XREF)));
        when(certificateRepository
            .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
            .thenReturn(Optional.of(buildCert("RENEWING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<CertificateEventEntity> captor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(captor.capture());

        assertThat(captor.getValue().getEventType()).isEqualTo("RENEWAL_SUCCESS");
        assertThat(captor.getValue().getFromStatus()).isEqualTo("RENEWING");
        assertThat(captor.getValue().getToStatus()).isEqualTo("RENEW_SUCCESS");
    }

    // ------------------------------------------------------------------ //
    //  Flow 3: Cert Deployment (CERT_DEPLOYMENT_RESPONSE)
    // ------------------------------------------------------------------ //

    @Test
    void deploymentSuccess_updatesCertToActive() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));

        boolean completed = process("CERT_DEPLOYMENT_RESPONSE", deploymentResponse());

        verify(certificateRepository, never()).save(any());
        // ORGANIZATION_ID ("organization-") is not numeric and the fixture is unverified, so
        // organizationOf() falls back to null here — real traffic always carries a numeric id.
        verify(deploymentExecutionService).handleAgentSuccess(
                eq(REQ_ID),
                isNull(),
                eq("https://target-vault.vault.azure.net/certificates/live-cert"),
                any());
        assertThat(completed).isTrue();
    }

    @Test
    void deploymentSuccess_publishesNotificationWithTargetTypeResultRespondedAt() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));

        process("CERT_DEPLOYMENT_RESPONSE", deploymentResponse());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher).publish(
                eq("CERT_DEPLOYMENT_SUCCESS"), eq(ORGANIZATION_ID), eq(XREF), captor.capture());

        Map<String, Object> fields = captor.getValue();
        assertThat(fields).containsEntry("targetType", "AZURE_KV");
        assertThat(fields).containsEntry("result", "DEPLOYED");
        assertThat(fields).containsEntry("respondedAt", "2026-03-14T10:30:00Z");
    }

    @Test
    void deploymentSuccess_insertsEventWithTargetInfo() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));

        process("CERT_DEPLOYMENT_RESPONSE", deploymentResponse());

        ArgumentCaptor<CertificateEventEntity> captor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(captor.capture());

        assertThat(captor.getValue().getEventType()).isEqualTo("DEPLOYMENT_SUCCESS");
        assertThat(captor.getValue().getToStatus()).isEqualTo("ACTIVE");
        assertThat(captor.getValue().getDetails()).contains("AZURE_KV");
        assertThat(captor.getValue().getDetails()).contains("target-vault");
    }

    // ------------------------------------------------------------------ //
    //  Error flow: AGENT_ERROR
    // ------------------------------------------------------------------ //

    @Test
    void agentError_discovery_marksDiscoveryFailedWithoutCertificateHandling() throws Exception {
        AgentErrorMessage error = agentError(
                "CERT_DISCOVERY",
                "DISCOVERY_K8S_SECRET_LIST_FAILED",
                "list Kubernetes Secrets for discovery namespace=team-a failed (HTTP 403)");
        error.setCertificateXref(null);
        error.setOrganizationId(CERT_ORGANIZATION_ID_STR);

        boolean completed = process("AGENT_ERROR", error);

        assertThat(completed).isTrue();
        verify(discoveryService).markDiscoveryAgentFailed(
                REQ_ID,
                CERT_ORGANIZATION_,
                "DISCOVERY_K8S_SECRET_LIST_FAILED",
                "list Kubernetes Secrets for discovery namespace=team-a failed (HTTP 403)");
        verify(certificateRepository, never()).findByCertificateXref(any());
        verify(deploymentExecutionService, never()).handleAgentFailure(any(), any(), any(), any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void agentError_discoveryWithoutRequestId_completesWithoutRetryingPoisonMessage() throws Exception {
        AgentErrorMessage error = agentError(
                "CERT_DISCOVERY",
                "DISCOVERY_K8S_SECRET_LIST_FAILED",
                "list Kubernetes Secrets for discovery namespace=team-a failed (HTTP 403)");
        error.setRequestId(null);
        error.setCertificateXref(null);

        boolean completed = process("AGENT_ERROR", error);

        assertThat(completed).isTrue();
        verify(discoveryService, never()).markDiscoveryAgentFailed(any(), any(), any());
        verify(certificateRepository, never()).findByCertificateXref(any());
    }

    @Test
    void agentError_profileOperationRoutesCmsIssuedOperationCorrelation() throws Exception {
        AgentErrorMessage error = agentError(
                "IOT_CERTIFICATE_PROFILE_COMMAND", "INTUNE_PROFILE_CREATE_FAILED",
                "Graph rejected the profile");
        error.setOrganizationId(CERT_ORGANIZATION_ID_STR);
        error.setCertificateXref(null);
        error.setSourceXref("source-1");
        error.setRequestId("profile_op_123");
        error.setRespondedAt("2026-08-25T00:00:00Z");

        boolean completed = process("AGENT_ERROR", error);

        assertThat(completed).isTrue();
        verify(certificateProfileResponseHandler).handleOperationAgentError(
                "source-1", CERT_ORGANIZATION_, "profile_op_123",
                "INTUNE_PROFILE_CREATE_FAILED", "Graph rejected the profile",
                "2026-08-25T00:00:00Z");
        verify(certificateRepository, never()).findByCertificateXref(any());
    }

    @Test
    void agentError_profileSyncRoutesCmsIssuedRequestCorrelation() throws Exception {
        AgentErrorMessage error = agentError(
                "IOT_CERTIFICATE_PROFILE_SYNC_COMMAND", "INTUNE_PROFILE_LIST_FAILED",
                "Graph profile listing failed");
        error.setOrganizationId(CERT_ORGANIZATION_ID_STR);
        error.setCertificateXref(null);
        error.setSourceXref("source-1");
        error.setRequestId("profile_sync_123");
        error.setRespondedAt("2026-08-25T00:00:00Z");

        boolean completed = process("AGENT_ERROR", error);

        assertThat(completed).isTrue();
        verify(certificateProfileResponseHandler).handleSyncAgentError(
                "source-1", CERT_ORGANIZATION_, "profile_sync_123",
                "INTUNE_PROFILE_LIST_FAILED", "Graph profile listing failed",
                "2026-08-25T00:00:00Z");
        verify(certificateRepository, never()).findByCertificateXref(any());
    }

    @Test
    void agentError_issuance_marksFailedAndPublishesFailureNotification() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));

        process("AGENT_ERROR", agentError("CERT_ISSUANCE", "ACME_DNS_CHALLENGE_FAILED", "DNS TXT not found"));

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("FAILED");
        assertThat(certCaptor.getValue().getLastErrorCode()).isEqualTo("ACME_DNS_CHALLENGE_FAILED");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> notifCaptor = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher).publish(
                eq("CERT_ISSUANCE_FAILED"), eq(ORGANIZATION_ID), eq(XREF), notifCaptor.capture());
        assertThat(notifCaptor.getValue()).containsEntry("errorCode", "ACME_DNS_CHALLENGE_FAILED");

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getEventType()).isEqualTo("ISSUANCE_FAILED");
        assertThat(eventCaptor.getValue().getToStatus()).isEqualTo("FAILED");
    }

    @Test
    void agentError_issuanceAfterADuplicateDeliveryAlreadyIssuedIt_leavesTheCertificateActive() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));

        process("AGENT_ERROR", agentError("CERT_ISSUANCE", "ACME_ORDER_INVALID", "order already finalized"));

        verify(certificateRepository, never()).save(any());
        verify(eventRepository, never()).save(any());
        verify(alertRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void agentError_issuanceWhoseRequestAlreadySucceeded_isIgnoredByRequestId() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(eventRepository.existsByRequestIdAndEventType(REQ_ID, "ISSUANCE_FAILED")).thenReturn(false);
        when(eventRepository.existsByRequestIdAndEventType(REQ_ID, "ISSUANCE_SUCCESS")).thenReturn(true);

        process("AGENT_ERROR", agentError("CERT_ISSUANCE", "ACME_ORDER_INVALID", "order already finalized"));

        verify(certificateRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void agentError_renewalWhoseRequestAlreadyRenewed_doesNotRecordAFailure() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        when(eventRepository.existsByRequestIdAndEventType(REQ_ID, "RENEWAL_FAILED")).thenReturn(false);
        when(eventRepository.existsByRequestIdAndEventType(REQ_ID, "RENEWAL_SUCCESS")).thenReturn(true);

        process("AGENT_ERROR", agentError("CERT_RENEWAL", "ACME_CHALLENGE_FAILED", "Challenge timed out"));

        verify(renewalScheduleRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void agentError_deploymentWhoseRequestAlreadyDeployed_keepsTheSuccess() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        com.certmanagement.entity.DeploymentEntity deployed = new com.certmanagement.entity.DeploymentEntity();
        deployed.setStatus("SUCCESS");
        when(deploymentExecutionService.findDeployment(REQ_ID, null)).thenReturn(Optional.of(deployed));

        process("AGENT_ERROR", agentError("CERT_DEPLOYMENT", "AZURE_KV_AUTH_FAILED", "SP credentials expired"));

        verify(deploymentExecutionService, never()).handleAgentFailure(any(), any(), any(), any(), any());
        verify(eventRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void agentError_manualTxtRequest_marksFailed() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING_DNS")));

        process("AGENT_ERROR", agentError("CERT_MANUAL_TXT_REQUEST", "MANUAL_TXT_REQUEST_INVALID", "domain is required"));

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("FAILED");

        verify(notificationPublisher).publish(eq("CERT_ISSUANCE_FAILED"), eq(ORGANIZATION_ID), eq(XREF), any());
    }

    @Test
    void agentError_manualDnsValidate_marksFailed() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("VALIDATING")));

        process("AGENT_ERROR", agentError("CERT_MANUAL_DNS_VALIDATE", "ACME_CHALLENGE_FAILED", "DNS TXT not found"));

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("FAILED");

        verify(notificationPublisher).publish(eq("CERT_ISSUANCE_FAILED"), eq(ORGANIZATION_ID), eq(XREF), any());
    }

    @Test
    void agentError_renewal_updatesScheduleAndPublishesRenewalFailed() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));

        RenewalScheduleEntity schedule = buildSchedule();
        schedule.setEnabled(true);
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(schedule));

        process("AGENT_ERROR", agentError("CERT_RENEWAL", "ACME_CHALLENGE_FAILED", "Challenge timed out"));

        ArgumentCaptor<RenewalScheduleEntity> rsCaptor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(rsCaptor.capture());
        assertThat(rsCaptor.getValue().getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(rsCaptor.getValue().getNextAttemptAt()).isAfter(OffsetDateTime.now());
        assertThat(rsCaptor.getValue().getEnabled()).isTrue();

        verify(notificationPublisher).publish(eq("CERT_RENEWAL_FAILED"), any(), any(), any());

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getEventType()).isEqualTo("RENEWAL_FAILED");
    }

    @Test
    void agentError_renewalOnRenewedXref_updatesPreviousScheduleViaLookup() throws Exception {
        CertificateEntity renewedDraft = buildRenewedDraft(RENEWED_XREF);
        CertificateEntity previous = buildCert("RENEWING");

        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(renewedDraft));
        when(certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
                .thenReturn(Optional.of(previous));

        RenewalScheduleEntity schedule = buildSchedule();
        schedule.setEnabled(true);
        when(renewalScheduleRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.empty());
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(schedule));

        AgentErrorMessage error = agentError("CERT_RENEWAL", "ACME_CHALLENGE_FAILED", "Challenge timed out");
        error.setCertificateXref(RENEWED_XREF);
        process("AGENT_ERROR", error);

        ArgumentCaptor<RenewalScheduleEntity> rsCaptor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(rsCaptor.capture());
        assertThat(rsCaptor.getValue().getLastRenewalStatus()).isEqualTo("FAILED");
        assertThat(rsCaptor.getValue().getNextAttemptAt()).isAfter(OffsetDateTime.now());
        assertThat(rsCaptor.getValue().getEnabled()).isTrue();

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository, atLeastOnce()).save(certCaptor.capture());
        assertThat(certCaptor.getAllValues()).anySatisfy(saved -> {
            assertThat(saved.getCertificateXref()).isEqualTo(RENEWED_XREF);
            assertThat(saved.getStatus()).isEqualTo("RENEWAL_FAILED");
        });
        assertThat(certCaptor.getAllValues()).anySatisfy(saved -> {
            assertThat(saved.getCertificateXref()).isEqualTo(XREF);
            assertThat(saved.getStatus()).isEqualTo("ACTIVE");
        });
    }

    @Test
    void agentError_duplicateRequestId_suppressesAlertAndNotification() throws Exception {
        when(eventRepository.existsByRequestIdAndEventType(REQ_ID, "RENEWAL_FAILED")).thenReturn(true);

        process("AGENT_ERROR", agentError("CERT_RENEWAL", "ACME_CHALLENGE_FAILED", "Challenge timed out"));

        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
        verify(alertRepository, never()).save(any());
        verify(eventRepository, never()).save(any());
        verify(renewalScheduleRepository, never()).save(any());
    }

    @Test
    void issuanceSuccess_persistsOrderIdWhenPresent() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        CertIssuanceResponse response = issuanceResponse("ISSUED");
        response.setOrderId("digicert-order-123");

        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<CertificateEntity> captor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(captor.capture());
        assertThat(captor.getValue().getOrderId()).isEqualTo("digicert-order-123");
    }

    @Test
    void issuanceSuccess_keepsTheCaCostAndCustodyTheAgentReports() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        CertIssuanceResponse response = issuanceResponse("ISSUED");
        response.setCaOrderCost("7.50");
        response.setCaOrderCurrency("usd");
        response.setKeyCustody("CUSTOMER_HELD");

        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<CertificateEntity> captor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(captor.capture());
        assertThat(captor.getValue().getCaOrderCost()).isEqualByComparingTo("7.50");
        assertThat(captor.getValue().getCaOrderCurrency()).isEqualTo("USD");
        assertThat(captor.getValue().getKeyCustody()).isEqualTo(com.certmanagement.enums.KeyCustody.CUSTOMER_HELD);
    }

    @Test
    void issuanceSuccess_fromAnOlderAgent_leavesCostAndCustodyAlone() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse("ISSUED"));

        ArgumentCaptor<CertificateEntity> captor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(captor.capture());
        assertThat(captor.getValue().getCaOrderCost()).isNull();
        assertThat(captor.getValue().getKeyCustody()).isEqualTo(com.certmanagement.enums.KeyCustody.PLATFORM_HELD);
    }

    @Test
    void issuanceSuccess_syncsOrderIdToScheduleWhenPresent() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildSchedule()));

        CertIssuanceResponse response = issuanceResponse("ISSUED");
        response.setOrderId("digicert-order-111");

        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<RenewalScheduleEntity> rsCaptor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(rsCaptor.capture());
        assertThat(rsCaptor.getValue().getOrderId()).isEqualTo("digicert-order-111");
    }

    @Test
    void renewalSuccess_syncsOrderIdToScheduleWhenPresent() throws Exception {
        when(certificateRepository.findByCertificateXref(RENEWED_XREF)).thenReturn(Optional.of(buildRenewedDraft(RENEWED_XREF)));
        when(certificateRepository
            .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(UDC_ID, "RENEWING"))
            .thenReturn(Optional.of(buildCert("RENEWING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildSchedule()));

        CertIssuanceResponse response = issuanceResponse("RENEWED");
        response.setCertificateXref(RENEWED_XREF);
        response.setOrderId("digicert-order-222");

        process("CERT_ISSUANCE_RESPONSE", response);

        ArgumentCaptor<RenewalScheduleEntity> rsCaptor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(rsCaptor.capture());
        assertThat(rsCaptor.getValue().getOrderId()).isEqualTo("digicert-order-222");
        assertThat(rsCaptor.getValue().getCertificateXref()).isNotEqualTo(XREF);
    }

    // ------------------------------------------------------------------ //
    //  Revocation (CERT_REVOCATION_RESPONSE)
    // ------------------------------------------------------------------ //

    @Test
    void revocationSuccess_marksCertRevokedAndClearsErrors() throws Exception {
        CertificateEntity cert = buildCert("REVOKING");
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));

        boolean completed = process("CERT_REVOCATION_RESPONSE", revocationResponse());
        assertThat(completed).isTrue();

        ArgumentCaptor<CertificateEntity> captor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("REVOKED");
        assertThat(captor.getValue().getLastErrorCode()).isNull();

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getEventType()).isEqualTo("REVOCATION_SUCCESS");
        assertThat(eventCaptor.getValue().getToStatus()).isEqualTo("REVOKED");
    }

    @Test
    void revocationSuccess_publishesCertRevokedNotification() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("REVOKING")));

        process("CERT_REVOCATION_RESPONSE", revocationResponse());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> notifCaptor = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher).publish(
                eq("CERT_REVOKED"), eq(CERT_ORGANIZATION_ID_STR), eq(XREF), notifCaptor.capture());
        assertThat(notifCaptor.getValue()).containsKey("domain");
        assertThat(notifCaptor.getValue()).containsKey("reason");
    }

    @Test
    void revocationSuccess_organizationMismatch_skipsUpdateAndNotification() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("REVOKING")));

        CertRevocationResponse response = revocationResponse();
        response.setOrganizationId("99999999-9999-9999-9999-999999999999");

        process("CERT_REVOCATION_RESPONSE", response);

        verify(certificateRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(eq("CERT_REVOKED"), any(), any(), any());
    }

    @Test
    void revocationSuccess_alreadyRevoked_idempotentNoSave() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("REVOKED")));

        process("CERT_REVOCATION_RESPONSE", revocationResponse());

        verify(certificateRepository, never()).save(any());
    }

    @Test
    void revocationSuccess_notRevoking_skipsUpdate() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));

        process("CERT_REVOCATION_RESPONSE", revocationResponse());

        verify(certificateRepository, never()).save(any());
    }

    @Test
    void agentError_retryGiveUpWithAcmeRateLimited_alertContainsUserFacingTextAndRetryAfter() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));

        AgentErrorMessage error = agentError("CERT_ISSUANCE", "RETRY_GIVE_UP", "Gave up after 6 retries");
        error.setLastReason("ACME_RATE_LIMITED");
        error.setRetryAfterUtc("2026-06-25T03:00:00Z");

        process("AGENT_ERROR", error);

        ArgumentCaptor<AlertEntity> alertCaptor = ArgumentCaptor.forClass(AlertEntity.class);
        verify(alertRepository).save(alertCaptor.capture());
        AlertEntity saved = alertCaptor.getValue();

        assertThat(saved.getMessage())
                .contains("Let's Encrypt rate-limited")
                .contains("Try again after 2026-06-25T03:00:00Z.");
        assertThat(saved.getErrorCode()).isEqualTo("RETRY_GIVE_UP");
    }

    @Test
    void agentError_revocation_marksRevocationFailedAndNotification() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("REVOKING")));

        process("AGENT_ERROR", agentError("CERT_REVOCATION_COMMAND", "ACME_REVOKE_FAILED", "CA refused"));

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("REVOCATION_FAILED");

        verify(notificationPublisher).publish(
                eq("CERT_REVOCATION_FAILED"), eq(ORGANIZATION_ID), eq(XREF), any());

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getEventType()).isEqualTo("REVOCATION_FAILED");
        assertThat(eventCaptor.getValue().getToStatus()).isEqualTo("REVOCATION_FAILED");

        ArgumentCaptor<AlertEntity> alertCaptor = ArgumentCaptor.forClass(AlertEntity.class);
        verify(alertRepository).save(alertCaptor.capture());
        assertThat(alertCaptor.getValue().getAlertType()).isEqualTo(AlertTypeEnum.CERTIFICATE_FAILURE);
    }

    @Test
    void agentError_deployment_doesNotTouchRenewalSchedule() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));

        process("AGENT_ERROR", agentError("CERT_DEPLOYMENT", "AZURE_KV_AUTH_FAILED", "SP credentials expired"));

        verify(renewalScheduleRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
        verify(deploymentExecutionService).handleAgentFailure(
                eq(REQ_ID), isNull(), eq("AZURE_KV_AUTH_FAILED"), eq("SP credentials expired"), any());
        verify(notificationPublisher).publish(eq("CERT_DEPLOYMENT_FAILED"), any(), any(), any());

        ArgumentCaptor<CertificateEventEntity> eventCaptor = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(eventRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getEventType()).isEqualTo("DEPLOYMENT_FAILED");
    }

    // ------------------------------------------------------------------ //
    //  Message routing edge cases
    // ------------------------------------------------------------------ //

    @Test
    void unknownMessageType_isIgnoredAndMessageCompleted() {
        boolean completed = processRaw("COMPLETELY_UNKNOWN", "{}");

        verify(certificateRepository, never()).findByCertificateXref(any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
        assertThat(completed).isTrue();
    }

    @Test
    void malformedJson_abandonsMessageInsteadOfCompleting() {
        boolean abandoned = processAndExpectAbandon("CERT_ISSUANCE_RESPONSE", "{not-valid-json}");
        assertThat(abandoned).isTrue();
    }

    @Test
    void manualTxtResponse_persistsAcmeAccountHandleAndMovesCertAwaitingDns() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING_DNS")));

        boolean completed = process("CERT_MANUAL_TXT_RESPONSE", manualTxtResponse());
        assertThat(completed).isTrue();

        ArgumentCaptor<CertManualIssuanceStateEntity> stateCaptor = ArgumentCaptor.forClass(CertManualIssuanceStateEntity.class);
        verify(manualIssuanceStateRepository).save(stateCaptor.capture());
        assertThat(stateCaptor.getValue().getAcmeOrderUrl()).isEqualTo("https://acme.test/order/1");
        assertThat(stateCaptor.getValue().getAcmeAccountHandle()).isEqualTo("https://kv.vault.azure.net/secrets/acme");

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("AWAITING_DNS");
        assertThat(certCaptor.getValue().getAcmeAccountHandle()).isEqualTo("https://kv.vault.azure.net/secrets/acme");
    }

    @Test
    void manualTxtResponse_publishesTxtReadyNotification() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING_DNS")));

        process("CERT_MANUAL_TXT_RESPONSE", manualTxtResponse());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(notificationPublisher).publish(
                eq("CERT_MANUAL_TXT_READY"), eq(CERT_ORGANIZATION_ID_STR), eq(XREF), captor.capture());

        Map<String, Object> fields = captor.getValue();
        assertThat(fields).containsEntry("domain", "example.com");
        assertThat(fields).containsEntry("recordCount", "1");
        assertThat(fields).containsEntry("requestId", REQ_ID);
    }

    @Test
    void manualTxtResponse_cancelledManual_ignoresStaleResponse() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF))
                .thenReturn(Optional.of(buildCert("CANCELLED_MANUAL")));

        boolean completed = process("CERT_MANUAL_TXT_RESPONSE", manualTxtResponse());

        assertThat(completed).isTrue();
        verify(manualIssuanceStateRepository).deleteByCertXref(XREF);
        verify(manualIssuanceStateRepository, never()).save(any());
        verify(certificateRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(eq("CERT_MANUAL_TXT_READY"), any(), any(), any());
    }

    // ------------------------------------------------------------------ //
    //  Payload builders
    // ------------------------------------------------------------------ //

    private CertIssuanceResponse issuanceResponse(String status) {
        CertIssuanceResponse r = new CertIssuanceResponse();
        r.setRequestId(REQ_ID);
        r.setCorrelationId(CORR_ID);
        r.setOrganizationId(ORGANIZATION_ID);
        r.setCertificateXref(XREF);
        r.setStatus(status);
        r.setCaProvider(CaProvider.LETS_ENCRYPT);
        r.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");
        r.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme");
        r.setIssuer("Let's Encrypt");
        r.setSerialNumber("04:AB:CD");
        r.setFingerprintSha256("sha256:abc");
        r.setValidFrom(VALID_FROM);
        r.setValidTo(VALID_TO);
        r.setRespondedAt("2026-03-14T10:30:00Z");
        return r;
    }

    private CertManualTxtResponse manualTxtResponse() {
        CertManualTxtResponse response = new CertManualTxtResponse();
        response.setRequestId(REQ_ID);
        response.setCorrelationId(CORR_ID);
        response.setOrganizationId(ORGANIZATION_ID);
        response.setCertificateXref(XREF);
        response.setAcmeOrderUrl("https://acme.test/order/1");
        response.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme");
        CertManualTxtResponse.TxtRecord record = new CertManualTxtResponse.TxtRecord();
        record.setRecordName("_acme-challenge.example.com");
        record.setRecordValue("digest");
        record.setDomain("example.com");
        response.setTxtRecords(List.of(record));
        response.setRespondedAt("2026-03-14T10:30:00Z");
        return response;
    }

    private CertDeploymentResponse deploymentResponse() {
        CertDeploymentResponse r = new CertDeploymentResponse();
        r.setRequestId(REQ_ID);
        r.setCorrelationId(CORR_ID);
        r.setOrganizationId(ORGANIZATION_ID);
        r.setCertificateXref(XREF);
        r.setStatus("DEPLOYED");
        r.setTargetType(TargetType.AZURE_KV);
        r.setTargetResourceId("https://target-vault.vault.azure.net/certificates/live-cert");
        r.setRespondedAt("2026-03-14T10:30:00Z");
        return r;
    }

    private AgentErrorMessage agentError(String originalMessageType, String errorCode, String errorDetail) {
        AgentErrorMessage e = new AgentErrorMessage();
        e.setRequestId(REQ_ID);
        e.setCorrelationId(CORR_ID);
        e.setOrganizationId(ORGANIZATION_ID);
        e.setCertificateXref(XREF);
        e.setOriginalMessageType(originalMessageType);
        e.setErrorCode(errorCode);
        e.setErrorDetail(errorDetail);
        return e;
    }

    private CertRevocationResponse revocationResponse() {
        CertRevocationResponse r = new CertRevocationResponse();
        r.setRequestId(REQ_ID);
        r.setCorrelationId(CORR_ID);
        r.setOrganizationId(CERT_ORGANIZATION_ID_STR);
        r.setCertificateXref(XREF);
        r.setCaProvider(CaProvider.LETS_ENCRYPT);
        r.setRevocationReason("UNSPECIFIED");
        return r;
    }

    /**
     * These fixtures exercise handler behaviour, not authentication, so they run with an
     * unscoped context. Gateway authentication is covered by
     * {@code PostgresTransportPostgresTest}, and cross-tenant rejection by the
     * organization-scoping cases at the bottom of {@code CertResponseProcessorMoreTest}.
     */
    private com.certmanagement.messaging.security.VerifiedAgentMessage verifiedFor(String messageType) {
        return com.certmanagement.messaging.security.VerifiedAgentMessage.unverified(
                null, messageType, "test-message-id", java.time.OffsetDateTime.now());
    }
}
