// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertDeploymentCommand;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.cert.AkamaiSpecialIssuanceService;
import com.certmanagement.service.cert.CredentialReferenceService;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DeploymentExecutionServiceTest {

    @Mock private CredentialReferenceService       credentialService;
    @Mock private CertAgentPublisher               publisher;
    @Mock private DeploymentTrackingService        trackingService;
    @Mock private UserDomainCertRepository         udcRepository;
    @Mock private RenewalScheduleRepository        renewalScheduleRepository;
    @Mock private DomainCredentialConfigRepository domainCredConfigRepository;
    @Mock private CertDeploymentConfigService      certDeploymentConfigService;
    @Mock private CertificateRepository            certificateRepository;
    @Mock private AkamaiSpecialIssuanceService     akamaiSpecialIssuanceService;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;
    @Mock private com.certmanagement.service.FeatureFlagService featureFlagService;

    private DeploymentExecutionService service;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private static final Long   ORG_ID       = 1L;
    private static final Long   UDC_ID       = 2L;
    private static final String CERT_XREF    = "cert-abc";
    private static final String CRED_XREF    = "cred-deploy";
    private static final String CERT_KV_PATH = "https://kv.vault.azure.net/secrets/cert";
    private static final String CRED_KV_PATH = "https://kv.vault.azure.net/secrets/deploy-cred";

    @BeforeEach
    void setUp() {
        service = new DeploymentExecutionService(credentialService, publisher, trackingService, udcRepository,
                renewalScheduleRepository, domainCredConfigRepository, certDeploymentConfigService,
                                certificateRepository, akamaiSpecialIssuanceService, objectMapper, orgTypeResolver,
                                featureFlagService, org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
        org.mockito.Mockito.lenient().when(orgTypeResolver.resolve(org.mockito.ArgumentMatchers.any(Long.class)))
                .thenReturn("B2B");
    }

    // ================================================================== //
    //  dispatchSingle()
    // ================================================================== //

    @Test
    void dispatchSingle_happyPath_createsTrackingRecordAndPublishes() {
        CertificateEntity cert = buildCert();
        CredentialReferenceEntity cred = buildDeployCred("AZURE_KV");

        service.dispatchSingle(ORG_ID, cert, CERT_KV_PATH, CRED_XREF, cred,
                "req-1", "corr-1", "MANUAL", null);

        verify(trackingService).createRequested(
                eq("req-1"), eq("corr-1"), eq(ORG_ID), eq(CERT_XREF), eq(UDC_ID),
                eq(CRED_XREF), eq("AZURE_KV"), eq("MANUAL"),
                eq(CERT_KV_PATH), eq(CRED_KV_PATH), eq(Map.of("triggeredBy", "manual")));

        ArgumentCaptor<CertDeploymentCommand> cmdCaptor =
                ArgumentCaptor.forClass(CertDeploymentCommand.class);
        verify(publisher).publishDeployment(cmdCaptor.capture());
        CertDeploymentCommand cmd = cmdCaptor.getValue();
        assertThat(cmd.getCertificateXref()).isEqualTo(CERT_XREF);
        assertThat(cmd.getDomain()).isEqualTo("example.com");
        assertThat(cmd.getCertSecretHandle()).isEqualTo(CERT_KV_PATH);
        assertThat(cmd.getDeploymentCredHandle()).isEqualTo(CRED_KV_PATH);

        verify(trackingService).markPublished("req-1");
        verify(trackingService, never()).markPublishFailed(any(), any(), any());
    }

    @Test
    void dispatchSingle_publishFails_marksFailedAndThrows() {
        CertificateEntity cert = buildCert();
        CredentialReferenceEntity cred = buildDeployCred("AZURE_KV");
        doThrow(new RuntimeException("queue send failed")).when(publisher).publishDeployment(any());

        assertThatThrownBy(() ->
                service.dispatchSingle(ORG_ID, cert, CERT_KV_PATH, CRED_XREF, cred,
                        "req-1", "corr-1", "MANUAL", null))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("PUBLISH_FAILED");

        verify(trackingService).markPublishFailed(eq("req-1"), eq("QUEUE_PUBLISH_FAILED"), contains("queue send failed"));
        verify(trackingService, never()).markPublished(any());
    }

    @Test
    void dispatchSingle_domainFromCert_usedDirectly() {
        CertificateEntity cert = buildCert();
        cert.setUserDomainCert(UserDomainCertEntity.builder().id(UDC_ID).domain("direct.example.com").build());
        CredentialReferenceEntity cred = buildDeployCred("AZURE_KV");

        service.dispatchSingle(ORG_ID, cert, CERT_KV_PATH, CRED_XREF, cred,
                "req-1", "corr-1", "MANUAL", null);

        ArgumentCaptor<CertDeploymentCommand> cap = ArgumentCaptor.forClass(CertDeploymentCommand.class);
        verify(publisher).publishDeployment(cap.capture());
        assertThat(cap.getValue().getDomain()).isEqualTo("direct.example.com");
        verify(udcRepository, never()).findById(any());
    }

    @Test
    void dispatchSingle_domainFromUdc_fetchedWhenCertDomainBlank() {
        CertificateEntity cert = buildCert();
        cert.setUserDomainCert(null);   // getDomain() returns null, falls through to UDC repo lookup
        CredentialReferenceEntity cred = buildDeployCred("AZURE_KV");
        when(udcRepository.findById(UDC_ID))
                .thenReturn(Optional.of(UserDomainCertEntity.builder()
                        .id(UDC_ID).domain("udc.example.com").build()));

        service.dispatchSingle(ORG_ID, cert, CERT_KV_PATH, CRED_XREF, cred,
                "req-1", "corr-1", "MANUAL", null);

        ArgumentCaptor<CertDeploymentCommand> cap = ArgumentCaptor.forClass(CertDeploymentCommand.class);
        verify(publisher).publishDeployment(cap.capture());
        assertThat(cap.getValue().getDomain()).isEqualTo("udc.example.com");
    }

    // ================================================================== //
    //  dispatchAll()
    // ================================================================== //

    @Test
    void dispatchAll_singleTarget_happyPath_publishesAndTracks() {
        CertificateEntity cert = buildCert();
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "AZURE_KV", CRED_KV_PATH);

        service.dispatchAll(ORG_ID, cert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        verify(trackingService).createRequested(
                any(), any(), eq(ORG_ID), eq(CERT_XREF), eq(UDC_ID),
                eq(CRED_XREF), eq("AZURE_KV"), eq("AUTO_POST_ISSUANCE"),
                eq(CERT_KV_PATH), eq(CRED_KV_PATH), eq(Map.of("triggeredBy", "auto")));
        verify(publisher).publishDeployment(any());
        verify(trackingService).markPublished(any());
    }

    @Test
    void dispatchAll_multipleTargets_allPublished() {
        CertificateEntity cert = buildCert();
        stubActiveCred("cred-1", "DEPLOYMENT", "AZURE_KV",  "kv/cred-1");
        stubActiveCred("cred-2", "DEPLOYMENT", "AWS_ACM",   "kv/cred-2");

        service.dispatchAll(ORG_ID, cert, CERT_KV_PATH, List.of("cred-1", "cred-2"), "AUTO_POST_RENEWAL");

        verify(publisher, times(2)).publishDeployment(any());
        verify(trackingService, times(2)).markPublished(any());
    }

    @Test
    void dispatchAll_wrongCredType_skipsTargetWithoutCreatingRecord() {
        CertificateEntity cert = buildCert();
        stubActiveCred(CRED_XREF, "DNS", "AZURE_DNS", CRED_KV_PATH);

        service.dispatchAll(ORG_ID, cert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        verify(publisher, never()).publishDeployment(any());
        verify(trackingService, never()).createRequested(any(), any(), any(), any(), any(),
                any(), any(), any(), any(), any(), any());
    }

    @Test
    void dispatchAll_publishFails_logsAndContinuesToNextTarget() {
        CertificateEntity cert = buildCert();
        stubActiveCred("cred-fail", "DEPLOYMENT", "AZURE_KV", "kv/cred-fail");
        stubActiveCred("cred-ok",   "DEPLOYMENT", "AWS_ACM",  "kv/cred-ok");
        doThrow(new RuntimeException("queue down"))
                .when(publisher).publishDeployment(argThat(c -> "kv/cred-fail".equals(c.getDeploymentCredHandle())));

        service.dispatchAll(ORG_ID, cert, CERT_KV_PATH,
                List.of("cred-fail", "cred-ok"), "AUTO_POST_RENEWAL");

        // second target must still be published
        verify(publisher, times(2)).publishDeployment(any());
        verify(trackingService, times(1)).markPublished(any());
        verify(trackingService, times(1)).markPublishFailed(any(), eq("QUEUE_PUBLISH_FAILED"), any());
    }

    @Test
    void dispatchAll_emptyTargets_noOp() {
        service.dispatchAll(ORG_ID, buildCert(), CERT_KV_PATH, List.of(), "AUTO_POST_ISSUANCE");

        verify(publisher, never()).publishDeployment(any());
        verify(trackingService, never()).createRequested(any(), any(), any(), any(), any(),
                any(), any(), any(), any(), any(), any());
    }

    @Test
    void dispatchAll_inactiveCred_logsAndContinues() {
        CertificateEntity cert = buildCert();
        when(credentialService.getByXref(ORG_ID, CRED_XREF))
                .thenReturn(CredentialReferenceEntity.builder()
                        .credentialXref(CRED_XREF).type("DEPLOYMENT")
                        .provider("AZURE_KV").secretHandle(CRED_KV_PATH).status("INACTIVE").build());

        // must not throw
        service.dispatchAll(ORG_ID, cert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        verify(publisher, never()).publishDeployment(any());
    }

    @Test
    void dispatchAll_missingDomainAndNullUdcId_throwsFromDoDispatch_caughtAndContinues() {
        CertificateEntity cert = buildCert();
        cert.setUserDomainCert(null);
        cert.setUserDomainCertId(null);
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "AZURE_KV", CRED_KV_PATH);

        // BadRequestException from resolveDeploymentDomain is caught by dispatchAll's try-catch
        service.dispatchAll(ORG_ID, cert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        verify(publisher, never()).publishDeployment(any());
    }

    @Test
    void dispatchSingle_missingDomainAndNullUdcId_throwsBadRequest() {
        CertificateEntity cert = buildCert();
        cert.setUserDomainCert(null);
        cert.setUserDomainCertId(null);
        CredentialReferenceEntity cred = buildDeployCred("AZURE_KV");

        assertThatThrownBy(() ->
                service.dispatchSingle(ORG_ID, cert, CERT_KV_PATH, CRED_XREF, cred,
                        "req-1", "corr-1", "MANUAL", null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("domain is missing");
    }

    @Test
    void dispatchSingle_kubernetesWithoutStoredConfig_marksFailedAndThrows() {
        CertificateEntity cert = buildCert();
        CredentialReferenceEntity cred = buildDeployCred("KUBERNETES_SECRETS");
        when(certDeploymentConfigService.findReconciledConfigJson(ORG_ID, UDC_ID, cred)).thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                service.dispatchSingle(ORG_ID, cert, CERT_KV_PATH, CRED_XREF, cred,
                        "req-1", "corr-1", "MANUAL", null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Kubernetes deployment config not found");

        verify(trackingService).markFailed(eq("req-1"), eq("DEPLOYMENT_CONFIG_MISSING"), any(), any());
        verify(publisher, never()).publishDeployment(any());
    }

    @Test
    void dispatchAll_kubernetesWithStoredConfig_publishesStoredConfig() {
        CertificateEntity cert = buildCert();
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "KUBERNETES_SECRETS", CRED_KV_PATH);
        CredentialReferenceEntity cred = credentialService.getByXref(ORG_ID, CRED_XREF);
        when(certDeploymentConfigService.findReconciledConfigJson(ORG_ID, UDC_ID, cred))
                .thenReturn(Optional.of("{\"clusterName\":\"prod\",\"authProvider\":\"AWS\",\"nsMaps\":[{\"dev\":\"example-dev-tls\"}]}"));

        service.dispatchAll(ORG_ID, cert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_RENEWAL");

        ArgumentCaptor<CertDeploymentCommand> cap = ArgumentCaptor.forClass(CertDeploymentCommand.class);
        verify(publisher).publishDeployment(cap.capture());
        assertThat(cap.getValue().getConfigJson()).contains("example-dev-tls");
    }

    @Test
    void dispatchSingle_kubernetesIgnoresOverrideAndUsesStoredConfig() {
        CertificateEntity cert = buildCert();
        CredentialReferenceEntity cred = buildDeployCred("KUBERNETES_SECRETS");
        when(certDeploymentConfigService.findReconciledConfigJson(ORG_ID, UDC_ID, cred))
                .thenReturn(Optional.of("{\"clusterName\":\"prod\",\"authProvider\":\"AWS\",\"nsMaps\":[{\"dev\":\"from-table\"}]}"));

        service.dispatchSingle(ORG_ID, cert, CERT_KV_PATH, CRED_XREF, cred,
                "req-1", "corr-1", "MANUAL", "{\"nsMaps\":[{\"dev\":\"override\"}]}");

        ArgumentCaptor<CertDeploymentCommand> cap = ArgumentCaptor.forClass(CertDeploymentCommand.class);
        verify(publisher).publishDeployment(cap.capture());
        assertThat(cap.getValue().getConfigJson()).contains("from-table").doesNotContain("override");
    }

    // ================================================================== //
    //  dispatchForCert()
    // ================================================================== //

    @Test
    void planAutoDeploy_readsOnly_andReportsWhatADispatchWouldDo() {
        CertificateEntity cert = buildCert();
        stubScheduleAndCredConfig(List.of(CRED_XREF));

        assertThat(service.planAutoDeploy(cert, true)).isEqualTo(DeploymentExecutionService.AutoDeployOutcome.DISPATCHED);
        assertThat(service.planAutoDeploy(cert, false))
                .isEqualTo(DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF);
        verify(publisher, never()).publishDeployment(any());
        org.mockito.Mockito.verifyNoInteractions(trackingService);
    }

    @Test
    void planAutoDeploy_withoutTargets_hasNothingToDeployEvenWhenDeploymentIsOff() {
        CertificateEntity cert = buildCert();
        stubScheduleAndCredConfig(List.of());

        assertThat(service.planAutoDeploy(cert, false))
                .isEqualTo(DeploymentExecutionService.AutoDeployOutcome.NOTHING_TO_DEPLOY);
    }

    @Test
    void dispatchForCert_withTargets_callsDispatchAll() {
        CertificateEntity cert = buildCert();
        stubScheduleAndCredConfig(List.of(CRED_XREF));
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "AZURE_KV", CRED_KV_PATH);
        when(featureFlagService.isEnabled(com.certmanagement.constants.FeatureFlags.CERTIFICATE_DEPLOYMENT, ORG_ID))
                .thenReturn(true);

        DeploymentExecutionService.AutoDeployOutcome outcome =
                service.dispatchForCert(cert, CERT_KV_PATH, ORG_ID.toString(), "AUTO_POST_ISSUANCE");

        assertThat(outcome).isEqualTo(DeploymentExecutionService.AutoDeployOutcome.DISPATCHED);
        verify(publisher).publishDeployment(any());
        verify(trackingService).markPublished(any());
    }

    @Test
    void dispatchForCert_deploymentFeatureOff_skipsAndSaysSo() {
        CertificateEntity cert = buildCert();
        stubScheduleAndCredConfig(List.of(CRED_XREF));
        when(featureFlagService.isEnabled(com.certmanagement.constants.FeatureFlags.CERTIFICATE_DEPLOYMENT, ORG_ID))
                .thenReturn(false);

        DeploymentExecutionService.AutoDeployOutcome outcome =
                service.dispatchForCert(cert, CERT_KV_PATH, ORG_ID.toString(), "AUTO_POST_RENEWAL");

        assertThat(outcome).isEqualTo(DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF);
        verify(publisher, never()).publishDeployment(any());
        verify(trackingService, never()).markPublished(any());
    }

    @Test
    void dispatchForCert_noSchedule_skipsWithoutError() {
        CertificateEntity cert = buildCert();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.empty());

        service.dispatchForCert(cert, CERT_KV_PATH, ORG_ID.toString(), "AUTO_POST_RENEWAL");

        verify(publisher, never()).publishDeployment(any());
    }

    @Test
    void dispatchForCert_noCredConfig_skipsWithoutError() {
        CertificateEntity cert = buildCert();
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(CERT_XREF).domainCredentialConfigId(99L).build();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.of(schedule));
        when(domainCredConfigRepository.findById(99L)).thenReturn(Optional.empty());

        service.dispatchForCert(cert, CERT_KV_PATH, ORG_ID.toString(), "AUTO_POST_RENEWAL");

        verify(publisher, never()).publishDeployment(any());
    }

    @Test
    void dispatchForCert_emptyTargets_skipsWithoutError() {
        CertificateEntity cert = buildCert();
        stubScheduleAndCredConfig(List.of());

        assertThat(service.dispatchForCert(cert, CERT_KV_PATH, ORG_ID.toString(), "AUTO_POST_ISSUANCE"))
                .isEqualTo(DeploymentExecutionService.AutoDeployOutcome.NOTHING_TO_DEPLOY);

        verify(publisher, never()).publishDeployment(any());
        verify(featureFlagService, never()).isEnabled(any(), any());
    }

    // ================================================================== //
    //  handleAgentSuccess / handleAgentFailure / findDeployment
    // ================================================================== //

    @Test
    void handleAgentSuccess_delegatesToTrackingService() {
        java.time.OffsetDateTime now = java.time.OffsetDateTime.now();

        service.handleAgentSuccess("req-1", "https://vault/certs/live", now);

        verify(trackingService).markSuccess("req-1", "https://vault/certs/live", now);
    }

    @Test
    void handleAgentFailure_delegatesToTrackingService() {
        java.time.OffsetDateTime now = java.time.OffsetDateTime.now();

        service.handleAgentFailure("req-1", "AZURE_KV_AUTH_FAILED", "SP expired", now);

        verify(trackingService).markFailed("req-1", "AZURE_KV_AUTH_FAILED", "SP expired", now);
    }

    @Test
    void findDeployment_delegatesToTrackingService() {
        when(trackingService.findByRequestId("req-1")).thenReturn(Optional.empty());

        Optional<com.certmanagement.entity.DeploymentEntity> result = service.findDeployment("req-1");

        assertThat(result).isEmpty();
        verify(trackingService).findByRequestId("req-1");
    }

    // ================================================================== //
    //  AKAMAI_CPS dispatch
    // ================================================================== //

    @Test
    void dispatchAll_akamaiCpsCredential_activeSpecialCertExists_deploysDirectly() {
        CertificateEntity regularCert = buildCert();
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "AKAMAI_CPS", CRED_KV_PATH);

        CertificateEntity akamaiSpecialCert = CertificateEntity.builder()
                .certificateXref("cert-akamai-special")
                .userDomainCertId(UDC_ID)
                .userDomainCert(regularCert.getUserDomainCert())
                .status("ACTIVE")
                .certSecretHandle("https://kv.vault.azure.net/secrets/akamai-cert")
                .specialCertificateType("AKAMAI_CPS")
                .build();

        stubScheduleAndCredConfigWithDns();
        when(certificateRepository.findTopByUdcIdAndSpecialTypeAndStatus(
                UDC_ID, "AKAMAI_CPS", CertificateStatus.ACTIVE.name()))
                .thenReturn(Optional.of(akamaiSpecialCert));

        service.dispatchAll(ORG_ID, regularCert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        ArgumentCaptor<CertDeploymentCommand> cap = ArgumentCaptor.forClass(CertDeploymentCommand.class);
        verify(publisher).publishDeployment(cap.capture());
        assertThat(cap.getValue().getCertificateXref()).isEqualTo("cert-akamai-special");
        assertThat(cap.getValue().getCertSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/akamai-cert");
        verify(akamaiSpecialIssuanceService, never()).triggerAkamaiSpecialIssuance(any(), any(), any(), any(), any());
    }

    @Test
    void dispatchAll_akamaiCpsCredential_noSpecialCertExists_triggersIssuance() {
        CertificateEntity regularCert = buildCert();
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "AKAMAI_CPS", CRED_KV_PATH);

        stubScheduleAndCredConfigWithDns();
        when(certificateRepository.findTopByUdcIdAndSpecialTypeAndStatus(
                UDC_ID, "AKAMAI_CPS", CertificateStatus.ACTIVE.name()))
                .thenReturn(Optional.empty());
        when(certificateRepository.findTopByUdcIdAndSpecialTypeAndStatus(
                UDC_ID, "AKAMAI_CPS", CertificateStatus.PENDING.name()))
                .thenReturn(Optional.empty());

        service.dispatchAll(ORG_ID, regularCert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        verify(publisher, never()).publishDeployment(any());
        verify(akamaiSpecialIssuanceService).triggerAkamaiSpecialIssuance(
                eq(ORG_ID), eq(regularCert), any(), any(), any());
    }

    @Test
    void dispatchAll_akamaiCpsCredential_pendingSpecialCertExists_skips() {
        CertificateEntity regularCert = buildCert();
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "AKAMAI_CPS", CRED_KV_PATH);

        stubScheduleAndCredConfigWithDns();
        when(certificateRepository.findTopByUdcIdAndSpecialTypeAndStatus(
                UDC_ID, "AKAMAI_CPS", CertificateStatus.ACTIVE.name()))
                .thenReturn(Optional.empty());
        when(certificateRepository.findTopByUdcIdAndSpecialTypeAndStatus(
                UDC_ID, "AKAMAI_CPS", CertificateStatus.PENDING.name()))
                .thenReturn(Optional.of(buildCert("PENDING")));

        service.dispatchAll(ORG_ID, regularCert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        verify(publisher, never()).publishDeployment(any());
        verify(akamaiSpecialIssuanceService, never()).triggerAkamaiSpecialIssuance(any(), any(), any(), any(), any());
    }

    @Test
    void dispatchAll_akamaiCpsCredential_noDnsConfig_skipsWithoutIssuance() {
        CertificateEntity regularCert = buildCert();
        stubActiveCred(CRED_XREF, "DEPLOYMENT", "AKAMAI_CPS", CRED_KV_PATH);

        // CredConfig with empty DNS config (manual cert)
        Long configId = 3L;
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(CERT_XREF).domainCredentialConfigId(configId).build();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.of(schedule));
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(configId).dnsConfig(Map.of()).deploymentTargets(List.of(CRED_XREF)).build();
        when(domainCredConfigRepository.findById(configId)).thenReturn(Optional.of(credConfig));

        service.dispatchAll(ORG_ID, regularCert, CERT_KV_PATH, List.of(CRED_XREF), "AUTO_POST_ISSUANCE");

        verify(publisher, never()).publishDeployment(any());
        verify(akamaiSpecialIssuanceService, never()).triggerAkamaiSpecialIssuance(any(), any(), any(), any(), any());
    }

    // ================================================================== //
    //  Helpers
    // ================================================================== //

    private CertificateEntity buildCert() {
        return buildCert("ACTIVE");
    }

    private CertificateEntity buildCert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID).domain("example.com").build();
        return CertificateEntity.builder()
                .certificateXref(CERT_XREF)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .status(status)
                .certSecretHandle(CERT_KV_PATH)
                .validTo(OffsetDateTime.now().plusDays(60))
                .build();
    }

    private CredentialReferenceEntity buildDeployCred(String provider) {
        return CredentialReferenceEntity.builder()
                .id(11L)
                .credentialXref(CRED_XREF)
                .type("DEPLOYMENT")
                .provider(provider)
                .secretHandle(CRED_KV_PATH)
                .status("ACTIVE")
                .build();
    }

    private void stubScheduleAndCredConfig(List<String> targets) {
        Long configId = 3L;
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(CERT_XREF).domainCredentialConfigId(configId).build();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.of(schedule));
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(configId).deploymentTargets(targets).build();
        when(domainCredConfigRepository.findById(configId)).thenReturn(Optional.of(credConfig));
    }

    private void stubActiveCred(String xref, String type, String provider, String secretHandle) {
        when(credentialService.getByXref(ORG_ID, xref))
                .thenReturn(CredentialReferenceEntity.builder()
                        .id(11L)
                        .credentialXref(xref).type(type)
                        .provider(provider).secretHandle(secretHandle).status("ACTIVE").build());
    }

    private void stubScheduleAndCredConfigWithDns() {
        Long configId = 3L;
        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .certificateXref(CERT_XREF).domainCredentialConfigId(configId).build();
        when(renewalScheduleRepository.findByCertificateXref(CERT_XREF))
                .thenReturn(Optional.of(schedule));
        DomainCredentialConfigEntity credConfig = DomainCredentialConfigEntity.builder()
                .id(configId)
                .dnsConfig(Map.of("example.com", "dns-cred-xref"))
                .deploymentTargets(List.of(CRED_XREF))
                .build();
        when(domainCredConfigRepository.findById(configId)).thenReturn(Optional.of(credConfig));
    }
}
