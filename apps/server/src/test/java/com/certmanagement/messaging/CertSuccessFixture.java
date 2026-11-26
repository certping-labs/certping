// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
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
import com.certmanagement.service.AlertService;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.agent.AgentHealthService;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.deployment.DeploymentExecutionService.AutoDeployOutcome;
import com.certmanagement.service.discovery.DiscoveryService;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * A {@link CertResponseProcessor} over mocks for the issuance/renewal success tests, with the state a
 * redelivery must observe kept for real: the events saved, the deployments dispatched and the flags
 * switched off. The certificates are plain objects the handler mutates, as a committed row would be.
 */
final class CertSuccessFixture {

    static final String ORG = "1";
    static final long ORG_ID = 1L;
    static final long UDC_ID = 2L;
    static final long CONFIG_ID = 3L;
    static final String XREF = "cert-issued";
    static final String PREVIOUS_XREF = "cert-previous";
    static final String RENEWED_XREF = "cert-renewed";
    static final String REQ_ID = "req-success-1";
    static final String HANDLE = "https://kv.vault.azure.net/secrets/cert";

    final CertificateRepository certificates = mock(CertificateRepository.class);
    final CertificateEventRepository events = mock(CertificateEventRepository.class);
    final RenewalScheduleRepository schedules = mock(RenewalScheduleRepository.class);
    final DomainCredentialConfigRepository credConfigs = mock(DomainCredentialConfigRepository.class);
    final CertManualIssuanceStateRepository manualStates = mock(CertManualIssuanceStateRepository.class);
    final CertificateCryptoMetadataRepository cryptoMetadata = mock(CertificateCryptoMetadataRepository.class);
    final DeploymentRepository deployments = mock(DeploymentRepository.class);
    final DeploymentExecutionService deployer = mock(DeploymentExecutionService.class);
    final NotificationPublisher publisher = mock(NotificationPublisher.class);
    final FeatureLifecycleLock lock = mock(FeatureLifecycleLock.class);
    final FeatureFlagResolver resolver = mock(FeatureFlagResolver.class);

    final List<CertificateEventEntity> savedEvents = new ArrayList<>();
    final Set<String> dispatchedDeployments = new HashSet<>();
    final Set<String> featuresOff = new HashSet<>();
    final CertResponseProcessor processor;

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    CertSuccessFixture(TransactionTemplate transactions) {
        processor = new CertResponseProcessor(certificates, cryptoMetadata, events, schedules, credConfigs,
                manualStates, mock(CertIssuanceService.class), publisher, new AlertService(mock(AlertRepository.class), mock(com.certmanagement.service.audit.MonitoringAuditRecorder.class)),
                objectMapper, deployer, mock(CertDeploymentConfigService.class),
                mock(CredentialReferenceRepository.class), mock(AgentHealthService.class),
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
        keepState();
    }

    private void keepState() {
        lenient().when(events.save(any(CertificateEventEntity.class))).thenAnswer(call -> {
            savedEvents.add(call.getArgument(0));
            return call.getArgument(0);
        });
        lenient().when(events.existsByRequestIdAndEventType(anyString(), anyString())).thenAnswer(call ->
                savedEvents.stream().anyMatch(event -> call.getArgument(0).equals(event.getRequestId())
                        && call.getArgument(1).equals(event.getEventType())));
        lenient().when(resolver.resolveUncached(anyString(), any()))
                .thenAnswer(call -> !featuresOff.contains(call.<String>getArgument(0)));
        lenient().when(resolver.automaticWorkBlockerUncached(anyString(), any()))
                .thenAnswer(call -> FeatureFlags.automaticWorkKeys(call.<String>getArgument(0)).stream()
                        .filter(featuresOff::contains).findFirst());
        lenient().when(deployer.planAutoDeploy(any(), anyBoolean())).thenAnswer(call -> call.<Boolean>getArgument(1)
                ? AutoDeployOutcome.DISPATCHED : AutoDeployOutcome.SKIPPED_FEATURE_OFF);
        lenient().when(deployer.dispatchForCert(any(), any(), any(), anyString())).thenAnswer(call -> {
            dispatchedDeployments.add(call.<CertificateEntity>getArgument(0).getCertificateXref() + "|"
                    + call.getArgument(3));
            return AutoDeployOutcome.DISPATCHED;
        });
        lenient().when(deployments.existsByCertificateXrefAndFlowType(anyString(), anyString()))
                .thenAnswer(call -> dispatchedDeployments.contains(call.getArgument(0) + "|" + call.getArgument(1)));
        lenient().when(certificates.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                anyLong(), eq("ACTIVE"))).thenReturn(Optional.empty());
    }

    /** A PENDING issuance with a disabled schedule and a configuration with one target. */
    CertificateEntity pendingIssuance() {
        CertificateEntity cert = certificate(XREF, "PENDING");
        RenewalScheduleEntity schedule = schedule(XREF, false);
        lenient().when(certificates.findByCertificateXrefAndOrganizationId(XREF, ORG_ID)).thenReturn(Optional.of(cert));
        lenient().when(schedules.findByCertificateXref(XREF)).thenReturn(Optional.of(schedule));
        lenient().when(credConfigs.findById(CONFIG_ID)).thenReturn(Optional.of(DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID).userDomainCertId(UDC_ID).dnsConfig(Map.of()).deploymentTargets(List.of("cred-kv")).build()));
        return cert;
    }

    /** A renewal in flight: the RENEWING certificate, its renewed draft, and its (enabled) schedule. */
    RenewalScheduleEntity renewalInFlight() {
        CertificateEntity previous = certificate(PREVIOUS_XREF, "RENEWING");
        previous.setValidTo(OffsetDateTime.parse("2026-11-01T00:00:00Z"));
        CertificateEntity renewed = certificate(RENEWED_XREF, "PENDING");
        RenewalScheduleEntity schedule = schedule(PREVIOUS_XREF, true);
        lenient().when(certificates.findByCertificateXrefAndOrganizationId(RENEWED_XREF, ORG_ID))
                .thenReturn(Optional.of(renewed));
        lenient().when(certificates.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                UDC_ID, "RENEWING")).thenReturn(Optional.of(previous));
        lenient().when(certificates.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                UDC_ID, "RENEW_SUCCESS")).thenReturn(Optional.of(previous));
        lenient().when(schedules.findByCertificateXref(PREVIOUS_XREF)).thenReturn(Optional.of(schedule));
        return schedule;
    }

    CertIssuanceResponse response(String status, String xref) {
        CertIssuanceResponse response = new CertIssuanceResponse();
        response.setRequestId(REQ_ID);
        response.setCorrelationId("corr-1");
        response.setOrganizationId(ORG);
        response.setCertificateXref(xref);
        response.setStatus(status);
        response.setCaProvider(CaProvider.LETS_ENCRYPT);
        response.setCertSecretHandle(HANDLE);
        response.setIssuer("Let's Encrypt");
        response.setSerialNumber("04:AB:CD");
        response.setValidFrom("2026-10-01T00:00:00Z");
        response.setValidTo(OffsetDateTime.now().plusDays(90).toString());
        return response;
    }

    /** Delivers the response once; true when the message was completed, false when abandoned. */
    boolean deliver(CertIssuanceResponse response) throws Exception {
        AtomicBoolean completed = new AtomicBoolean();
        processor.process("CERT_ISSUANCE_RESPONSE", objectMapper.writeValueAsString(response),
                VerifiedAgentMessage.unverified(ORG, "CERT_ISSUANCE_RESPONSE", "msg-1", OffsetDateTime.now()),
                () -> completed.set(true), () -> { });
        return completed.get();
    }

    long eventsOfType(String eventType) {
        return savedEvents.stream().filter(event -> eventType.equals(event.getEventType())).count();
    }

    private static CertificateEntity certificate(String xref, String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder().id(UDC_ID).organizationId(ORG_ID)
                .domain("example.com").build();
        return CertificateEntity.builder().certificateXref(xref).userDomainCertId(UDC_ID).userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT).status(status).certSecretHandle(HANDLE).build();
    }

    private static RenewalScheduleEntity schedule(String xref, boolean enabled) {
        return RenewalScheduleEntity.builder().certificateXref(xref).domainCredentialConfigId(CONFIG_ID)
                .caProvider(CaProvider.LETS_ENCRYPT).renewalWindowDays(30).enabled(enabled).build();
    }
}
