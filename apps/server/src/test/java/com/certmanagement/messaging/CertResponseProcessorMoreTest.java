// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.entity.CertificateCryptoMetadataEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DeploymentEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.exception.UnknownOrganizationForHeartbeatException;
import com.certmanagement.messaging.model.AgentDeepHealthCheckResponse;
import com.certmanagement.messaging.model.AgentHealthHeartbeat;
import com.certmanagement.messaging.model.CertDeploymentResponse;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateCryptoMetadataRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.AlertService;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.agent.AgentHealthService;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.discovery.DiscoveryService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertResponseProcessorMoreTest {

    @Mock private CertificateRepository                certificateRepository;
    @Mock private CertificateCryptoMetadataRepository  cryptoMetadataRepository;
    @Mock private CertificateEventRepository           eventRepository;
    @Mock private RenewalScheduleRepository            renewalScheduleRepository;
    @Mock private DomainCredentialConfigRepository     domainCredConfigRepository;
    @Mock private CertManualIssuanceStateRepository    manualIssuanceStateRepository;
    @Mock private CertIssuanceService                  certIssuanceService;
    @Mock private NotificationPublisher                notificationPublisher;
    @Mock private AlertRepository                       alertRepository;
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

    // Mirror the Spring Boot autoconfigured mapper: the ParameterNamesModule lets Jackson
    // bind records / @Builder-only DTOs (e.g. CertSecretDeleteResponse) that lack a no-arg ctor.
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private CertResponseProcessor processor;

    private static final String XREF             = "cert-abc123";
    private static final String ORGANIZATION_ID  = "organization-";

    private static final Long   CERT_ORGANIZATION = 1L;
    private static final Long   UDC_ID           = 2L;
    private static final String REQ_ID           = "req-";
    private static final String CORR_ID          = "corr-";

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
    }

    // --------------------------------------------------------------- //
    //  Helpers
    // --------------------------------------------------------------- //

    private UserDomainCertEntity buildUdc() {
        return UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(CERT_ORGANIZATION)
                .domain("example.com")
                .build();
    }

    private CertificateEntity buildCert(String status) {
        return CertificateEntity.builder()
                .id(99L)
                .certificateXref(XREF)
                .userDomainCertId(UDC_ID)
                .userDomainCert(buildUdc())
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .build();
    }

    private boolean process(String messageType, Object payload) throws Exception {
        String body = objectMapper.writeValueAsString(payload);
        AtomicBoolean completed = new AtomicBoolean(false);
        processor.process(messageType, body, verifiedFor(messageType), () -> completed.set(true), () -> {});
        return completed.get();
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

    private CertIssuanceResponse issuanceResponse() {
        CertIssuanceResponse r = new CertIssuanceResponse();
        r.setRequestId(REQ_ID);
        r.setCorrelationId(CORR_ID);
        r.setOrganizationId(ORGANIZATION_ID);
        r.setCertificateXref(XREF);
        r.setStatus("ISSUED");
        r.setCaProvider(CaProvider.LETS_ENCRYPT);
        r.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");
        r.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme");
        r.setIssuer("Let's Encrypt");
        r.setValidFrom("2026-03-14T00:00:00Z");
        r.setValidTo("2026-06-12T00:00:00Z");
        return r;
    }

    // --------------------------------------------------------------- //
    //  Deployment error branches
    // --------------------------------------------------------------- //

    @Test
    void deployment_nullTargetResourceId_recordsFailureAndAlert() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        CertDeploymentResponse r = deploymentResponse();
        r.setTargetResourceId(null);

        process("CERT_DEPLOYMENT_RESPONSE", r);

        verify(deploymentExecutionService).handleAgentFailure(
                eq(REQ_ID), isNull(), eq("INVALID_DEPLOYMENT_RESPONSE"), any(), any());
        verify(alertRepository).save(any());
        verify(notificationPublisher).publish(eq("CERT_DEPLOYMENT_FAILED"), eq(ORGANIZATION_ID), eq(XREF), any());
    }

    @Test
    void deployment_blankTargetResourceId_recordsFailure() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        CertDeploymentResponse r = deploymentResponse();
        r.setTargetResourceId("   ");

        process("CERT_DEPLOYMENT_RESPONSE", r);

        verify(deploymentExecutionService).handleAgentFailure(
                eq(REQ_ID), isNull(), eq("INVALID_DEPLOYMENT_RESPONSE"), any(), any());
    }

    @Test
    void deployment_malformedAzureKvResourceId_recordsFormatFailure() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        CertDeploymentResponse r = deploymentResponse();
        r.setTargetType(TargetType.AZURE_KV);
        r.setTargetResourceId("not-an-https-url");

        process("CERT_DEPLOYMENT_RESPONSE", r);

        verify(deploymentExecutionService).handleAgentFailure(
                eq(REQ_ID), isNull(), eq("INVALID_RESOURCE_ID_FORMAT"), any(), any());
        verify(notificationPublisher).publish(eq("CERT_DEPLOYMENT_FAILED"), eq(ORGANIZATION_ID), eq(XREF), any());
    }

    @Test
    void deployment_malformedAwsAcmResourceId_recordsFormatFailure() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        CertDeploymentResponse r = deploymentResponse();
        r.setTargetType(TargetType.AWS_ACM);
        r.setTargetResourceId("https://wrong-prefix");

        process("CERT_DEPLOYMENT_RESPONSE", r);

        verify(deploymentExecutionService).handleAgentFailure(
                eq(REQ_ID), isNull(), eq("INVALID_RESOURCE_ID_FORMAT"), any(), any());
    }

    @Test
    void deployment_unknownCert_skipsAllSideEffects() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());

        boolean completed = process("CERT_DEPLOYMENT_RESPONSE", deploymentResponse());

        assertThat(completed).isTrue();
        verify(deploymentExecutionService, never()).handleAgentSuccess(any(), any(), any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void deployment_withConfigJson_mergesAgentConfig() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        CertDeploymentResponse r = deploymentResponse();
        r.setConfigJson("{\"foo\":\"bar\"}");

        DeploymentEntity deployment = DeploymentEntity.builder()
                .deploymentCredentialXref("dep-cred-xref")
                .build();
        when(deploymentExecutionService.findDeployment(REQ_ID, null)).thenReturn(Optional.of(deployment));

        process("CERT_DEPLOYMENT_RESPONSE", r);

        verify(certDeploymentConfigService).mergeDeploymentResultFromAgent(
                eq(CERT_ORGANIZATION), eq(UDC_ID), eq("dep-cred-xref"), eq("AZURE_KV"), eq("{\"foo\":\"bar\"}"));
    }

    @Test
    void deployment_withConfigJsonButNoCredentialXref_doesNotMerge() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("ACTIVE")));
        CertDeploymentResponse r = deploymentResponse();
        r.setConfigJson("{\"foo\":\"bar\"}");

        DeploymentEntity deployment = DeploymentEntity.builder().build();
        when(deploymentExecutionService.findDeployment(REQ_ID, null)).thenReturn(Optional.of(deployment));

        process("CERT_DEPLOYMENT_RESPONSE", r);

        verify(certDeploymentConfigService, never()).mergeDeploymentResultFromAgent(any(), any(), any(), any(), any());
    }

    // --------------------------------------------------------------- //
    //  Agent health heartbeat
    // --------------------------------------------------------------- //

    @Test
    void heartbeat_persisted() throws Exception {
        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId("1");
        hb.setListening(true);
        when(agentHealthService.saveHeartbeat(any())).thenReturn(true);

        boolean completed = process("AGENT_HEALTH_HEARTBEAT", hb);

        assertThat(completed).isTrue();
        verify(agentHealthService).saveHeartbeat(any());
    }

    @Test
    void heartbeat_missingOrganizationId_skipsPersistence() throws Exception {
        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId(null);
        hb.setListening(true);

        boolean completed = process("AGENT_HEALTH_HEARTBEAT", hb);

        assertThat(completed).isTrue();
        verify(agentHealthService, never()).saveHeartbeat(any());
    }

    @Test
    void heartbeat_blankOrganizationId_skipsPersistence() throws Exception {
        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId("  ");

        process("AGENT_HEALTH_HEARTBEAT", hb);

        verify(agentHealthService, never()).saveHeartbeat(any());
    }

    @Test
    void heartbeat_unknownOrganization_swallowedAndCompletes() throws Exception {
        AgentHealthHeartbeat hb = new AgentHealthHeartbeat();
        hb.setOrganizationId("999");
        when(agentHealthService.saveHeartbeat(any()))
                .thenThrow(new UnknownOrganizationForHeartbeatException(999L));

        boolean completed = process("AGENT_HEALTH_HEARTBEAT", hb);

        assertThat(completed).isTrue();
    }

    // --------------------------------------------------------------- //
    //  Deep health, KV delete, discovery
    // --------------------------------------------------------------- //

    @Test
    void deepHealthResponse_ingested() throws Exception {
        AgentDeepHealthCheckResponse resp = new AgentDeepHealthCheckResponse();
        resp.setDeepCheckId("deep-1");
        resp.setOrganizationId("1");
        resp.setStatus("SUCCESS");

        boolean completed = process("AGENT_DEEP_HEALTH_CHECK_RESPONSE", resp);

        assertThat(completed).isTrue();
        verify(agentDeepHealthCheckService).ingestResponse(any());
    }

    private boolean processRaw(String messageType, String rawBody) {
        AtomicBoolean completed = new AtomicBoolean(false);
        processor.process(messageType, rawBody, verifiedFor(messageType), () -> completed.set(true), () -> {});
        return completed.get();
    }

    @Test
    void kvDeleteResponse_success_logsOnly() {
        String body = "{\"certificateXref\":\"" + XREF + "\",\"organizationId\":\"1\",\"status\":\"SUCCESS\"}";

        boolean completed = processRaw("CERT_SECRET_DELETE_RESPONSE", body);

        assertThat(completed).isTrue();
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    @Test
    void kvDeleteResponse_failure_logsWarning() {
        String body = "{\"certificateXref\":\"" + XREF + "\",\"organizationId\":\"1\","
                + "\"status\":\"FAILED\",\"errorCode\":\"KV_DELETE_FAILED\",\"errorDetail\":\"permission denied\"}";

        boolean completed = processRaw("CERT_SECRET_DELETE_RESPONSE", body);

        assertThat(completed).isTrue();
    }

    @Test
    void discoveryResponse_persistsResults() throws Exception {
        CertDiscoveryResponse resp = new CertDiscoveryResponse();
        resp.setRequestId(REQ_ID);
        resp.setOrganizationId("1");
        resp.setStatus("SUCCESS");
        resp.setBatchIndex(0);
        resp.setTotalBatches(1);

        boolean completed = process("CERT_DISCOVERY_RESPONSE", resp);

        assertThat(completed).isTrue();
        verify(discoveryService).persistDiscoveryResults(any(), any());
    }

    @Test
    void discoveryResponse_scopesToTheVerifiedOrganizationNotTheBody() throws Exception {
        // The gap this closes: a signed message may omit organizationId from its body entirely,
        // which slips past requireBodyOrganizationMatches (it only compares when the field is
        // present). Without the verified organization reaching the service, the discovery failure
        // path had nothing to scope by and would mark any named requestId's scan failed.
        CertDiscoveryResponse resp = new CertDiscoveryResponse();
        resp.setRequestId(REQ_ID);
        resp.setOrganizationId(null);
        resp.setStatus("FAILED");
        resp.setBatchIndex(0);
        resp.setTotalBatches(1);

        String body = objectMapper.writeValueAsString(resp);
        processor.process("CERT_DISCOVERY_RESPONSE", body, verifiedAs("42"), () -> {}, () -> {});

        verify(discoveryService).persistDiscoveryResults(any(), eq(42L));
    }

    @Test
    void discoveryComplete_marksComplete() throws Exception {
        DiscoveryCompleteMessage msg = new DiscoveryCompleteMessage();
        msg.setRequestId(REQ_ID);
        msg.setOrganizationId("1");
        msg.setTotalCerts(5);

        boolean completed = process("CERT_DISCOVERY_COMPLETE", msg);

        assertThat(completed).isTrue();
        verify(discoveryService).markDiscoveryComplete(any());
    }

    @Test
    void nullMessageType_isIgnoredAndCompleted() {
        AtomicBoolean completed = new AtomicBoolean(false);
        processor.process(null, "{}", verifiedFor(null), () -> completed.set(true), () -> {});
        assertThat(completed.get()).isTrue();
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
    }

    // --------------------------------------------------------------- //
    //  Crypto metadata upsert on issuance
    // --------------------------------------------------------------- //

    @Test
    void issuanceSuccess_withCryptoMetadata_upsertsMetadata() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(cryptoMetadataRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());

        CertIssuanceResponse r = issuanceResponse();
        r.setSubjectDn("CN=example.com");
        r.setCommonName("example.com");

        process("CERT_ISSUANCE_RESPONSE", r);

        ArgumentCaptor<CertificateCryptoMetadataEntity> captor =
                ArgumentCaptor.forClass(CertificateCryptoMetadataEntity.class);
        verify(cryptoMetadataRepository).save(captor.capture());
        assertThat(captor.getValue().getCommonName()).isEqualTo("example.com");
        assertThat(captor.getValue().getSubjectDn()).isEqualTo("CN=example.com");
    }

    @Test
    void issuanceSuccess_noCryptoMetadata_skipsUpsert() throws Exception {
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse());

        verify(cryptoMetadataRepository, never()).save(any());
    }

    // --------------------------------------------------------------- //
    //  Akamai-special post-issuance dispatch
    // --------------------------------------------------------------- //

    @Test
    void issuanceSuccess_akamaiSpecialCert_dispatchesToAkamaiTargets() throws Exception {
        CertificateEntity cert = buildCert("PENDING");
        cert.setSpecialCertificateType("AKAMAI_CPS");
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .userDomainCertId(UDC_ID)
                .deploymentTargets(List.of("akamai-cred-1"))
                .build();
        // domainCredConfigRepository is consulted twice: loadCredConfigForCert + akamai dispatch.
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID))
                .thenReturn(Optional.empty(), Optional.of(credConfig));

        CredentialReferenceEntity cred = new CredentialReferenceEntity();
        cred.setCredentialXref("akamai-cred-1");
        cred.setProvider("AKAMAI_CPS");
        when(credentialReferenceRepository.findByCredentialXref("akamai-cred-1"))
                .thenReturn(Optional.of(cred));

        when(deploymentExecutionService.isAutoDeployEnabled(1L)).thenReturn(true);

        CertIssuanceResponse r = issuanceResponse();
        r.setOrganizationId("1"); // numeric — dispatchAkamaiSpecialCert does Long.parseLong
        process("CERT_ISSUANCE_RESPONSE", r);

        verify(deploymentExecutionService, never())
                .dispatchForCert(any(), any(), any(), any());
        verify(deploymentExecutionService).dispatchAll(
                eq(1L), any(), any(), eq(List.of("akamai-cred-1")), eq("AUTO_POST_AKAMAI_ISSUANCE"));
    }

    @Test
    void issuanceSuccess_akamaiSpecialCert_deploymentOff_recordsTheSkipInsteadOfDispatching() throws Exception {
        CertificateEntity cert = buildCert("PENDING");
        cert.setSpecialCertificateType("AKAMAI_CPS");
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .userDomainCertId(UDC_ID)
                .deploymentTargets(List.of("akamai-cred-1"))
                .build();
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID))
                .thenReturn(Optional.empty(), Optional.of(credConfig));
        CredentialReferenceEntity cred = new CredentialReferenceEntity();
        cred.setCredentialXref("akamai-cred-1");
        cred.setProvider("AKAMAI_CPS");
        when(credentialReferenceRepository.findByCredentialXref("akamai-cred-1")).thenReturn(Optional.of(cred));
        when(deploymentExecutionService.isAutoDeployEnabled(1L)).thenReturn(false);

        CertIssuanceResponse r = issuanceResponse();
        r.setOrganizationId("1");
        process("CERT_ISSUANCE_RESPONSE", r);

        verify(deploymentExecutionService, never()).dispatchAll(anyLong(), any(), any(), any(), any());
        org.mockito.ArgumentCaptor<com.certmanagement.entity.CertificateEventEntity> events =
                org.mockito.ArgumentCaptor.forClass(com.certmanagement.entity.CertificateEventEntity.class);
        verify(eventRepository, org.mockito.Mockito.atLeastOnce()).save(events.capture());
        org.assertj.core.api.Assertions.assertThat(events.getAllValues())
                .extracting(com.certmanagement.entity.CertificateEventEntity::getEventType)
                .contains("AUTO_DEPLOY_SKIPPED_FEATURE_OFF");
    }

    @Test
    void issuanceSuccess_akamaiSpecialCert_noTargets_staysActive() throws Exception {
        CertificateEntity cert = buildCert("PENDING");
        cert.setSpecialCertificateType("AKAMAI_CPS");
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse());

        verify(deploymentExecutionService, never()).dispatchAll(anyLong(), any(), any(), any(), any());
        verify(deploymentExecutionService, never()).dispatchForCert(any(), any(), any(), any());
    }

    @Test
    void issuanceSuccess_akamaiSpecialCert_noAkamaiCredentials_doesNotDispatch() throws Exception {
        CertificateEntity cert = buildCert("PENDING");
        cert.setSpecialCertificateType("AKAMAI_CPS");
        when(certificateRepository.findByCertificateXref(XREF)).thenReturn(Optional.of(cert));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());

        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .userDomainCertId(UDC_ID)
                .deploymentTargets(List.of("non-akamai-cred"))
                .build();
        when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID))
                .thenReturn(Optional.empty(), Optional.of(credConfig));

        CredentialReferenceEntity cred = new CredentialReferenceEntity();
        cred.setCredentialXref("non-akamai-cred");
        cred.setProvider("AZURE_KV");
        when(credentialReferenceRepository.findByCredentialXref("non-akamai-cred"))
                .thenReturn(Optional.of(cred));

        process("CERT_ISSUANCE_RESPONSE", issuanceResponse());

        verify(deploymentExecutionService, never()).dispatchAll(anyLong(), any(), any(), any(), any());
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

    // --------------------------------------------------------------- //
    //  Organization scoping — a valid sender must not reach another tenant
    // --------------------------------------------------------------- //

    private com.certmanagement.messaging.security.VerifiedAgentMessage verifiedAs(String organizationId) {
        return new com.certmanagement.messaging.security.VerifiedAgentMessage(
                organizationId, "CERT_ISSUANCE_RESPONSE", "asb-msg-1",
                java.time.OffsetDateTime.now(), true);
    }

    @Test
    void authenticatedOrganizationCannotMutateAnotherTenantsCertificate() throws Exception {
        // The certificate exists, but belongs to organization 1. A verified message from
        // organization 99 naming it must change nothing: a valid signature proves who sent the
        // message, not that the xref inside belongs to them.
        lenient().when(certificateRepository.findByCertificateXref(XREF))
                .thenReturn(Optional.of(buildCert("PENDING")));
        lenient().when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, 99L))
                .thenReturn(Optional.empty());

        CertIssuanceResponse r = issuanceResponse();
        r.setOrganizationId("99");
        String body = objectMapper.writeValueAsString(r);

        AtomicBoolean completed = new AtomicBoolean(false);
        processor.process("CERT_ISSUANCE_RESPONSE", body, verifiedAs("99"),
                () -> completed.set(true), () -> {});

        verify(certificateRepository, never()).save(any());
        verify(notificationPublisher, never()).publish(any(), any(), any(), any());
        assertThat(completed.get()).isTrue();
    }

    @Test
    void authenticatedOrganizationCanMutateItsOwnCertificate() throws Exception {
        lenient().when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, CERT_ORGANIZATION))
                .thenReturn(Optional.of(buildCert("PENDING")));
        when(renewalScheduleRepository.findByCertificateXref(XREF)).thenReturn(Optional.empty());
        lenient().when(domainCredConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());

        CertIssuanceResponse r = issuanceResponse();
        r.setOrganizationId("1");
        String body = objectMapper.writeValueAsString(r);

        processor.process("CERT_ISSUANCE_RESPONSE", body, verifiedAs("1"), () -> {}, () -> {});

        verify(certificateRepository).save(any());
    }

    @Test
    void unverifiedHeaderAndBodyMustAlsoAgree() throws Exception {
        // Certificate lookups scope on the declared organization while handlers read ids from the
        // body, so the two must agree even when the message could not be authenticated —
        // otherwise a message is scoped as one tenant and processed as another.
        CertIssuanceResponse r = issuanceResponse();
        r.setOrganizationId("99");
        String body = objectMapper.writeValueAsString(r);

        com.certmanagement.messaging.security.VerifiedAgentMessage unverified =
                com.certmanagement.messaging.security.VerifiedAgentMessage.unverified(
                        "1", "CERT_ISSUANCE_RESPONSE", "asb-msg-1", java.time.OffsetDateTime.now());

        assertThatThrownBy(() -> processor.requireBodyOrganizationMatches(body, unverified))
                .isInstanceOf(com.certmanagement.messaging.security.AgentMessageVerificationException.class);
    }

    @Test
    void bodyClaimingAnotherOrganizationThanTheSignedOneIsRejected() throws Exception {
        // The signature covers a digest of the body, so these can only diverge if the agent signed
        // a payload belonging to another tenant.
        CertIssuanceResponse r = issuanceResponse();
        r.setOrganizationId("99");
        String body = objectMapper.writeValueAsString(r);

        // Checked beside verification so the message is dead-lettered rather than redelivered.
        assertThatThrownBy(() -> processor.requireBodyOrganizationMatches(body, verifiedAs("1")))
                .isInstanceOf(com.certmanagement.messaging.security.AgentMessageVerificationException.class)
                .satisfies(e -> assertThat(
                        ((com.certmanagement.messaging.security.AgentMessageVerificationException) e)
                                .isPermanent()).isTrue());
    }
}
