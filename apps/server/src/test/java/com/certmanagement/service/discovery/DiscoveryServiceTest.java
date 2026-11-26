// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.dto.discovery.DiscoveryRunResponse;
import com.certmanagement.entity.DiscoveryConfigEntity;
import com.certmanagement.entity.DiscoveryConfigStatus;
import com.certmanagement.entity.DiscoveryScanStatus;
import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.service.audit.DiscoveryAuditRecorder;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertDiscoveryCommand;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.DiscoveredCertEntry;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DiscoveryConfigRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DiscoveredCertObservationRepository;
import com.certmanagement.repository.DiscoveredCertObservationRepository.DiscoveredCertCredentialView;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.security.GatewayRequestContext;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryServiceTest {

    @Mock private com.certmanagement.service.FeatureFlagService featureFlagService;
    @Mock private CertAgentPublisher            certAgentPublisher;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;
    @Mock private DiscoveryConfigRepository     discoveryConfigRepository;
    @Mock private DiscoveredCertRepository      discoveredCertRepository;
    @Mock private DiscoveredCertObservationRepository discoveredCertObservationRepository;
    @Mock private CertificateRepository         certificateRepository;
    @Mock private DiscoveryScanService          discoveryScanService;
    @Mock private DiscoveryScopeKeyFactory      discoveryScopeKeyFactory;
    @Mock private KubernetesDiscoveryDataValidator kubernetesDataValidator;
    @Mock private DiscoveryAuditRecorder discoveryAudit;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private DiscoveryService service;

    private static final Long   ORG_ID       = 42L;
    private static final String CRED_XREF    = "cred-aws-acm-001";
    private static final String KV_PATH      = "https://kv-test.vault.azure.net/secrets/aws-cred";
    private static final String TARGET_TYPE  = "AWS_ACM";
    private static final String SCOPE_JSON   = "{\"authMode\":\"STATIC_KEYS\",\"region\":\"us-east-1\"}";

    @BeforeEach
    void setUp() {
        service = new DiscoveryService(
                certAgentPublisher,
                orgTypeResolver,
                credentialReferenceRepository,
                discoveryConfigRepository,
                discoveredCertRepository,
                discoveredCertObservationRepository,
                certificateRepository,
                discoveryScanService,
                discoveryScopeKeyFactory,
                kubernetesDataValidator,
                new DiscoveryCredentialPolicy(objectMapper),
                new DiscoveredCertMapper(),
                com.certmanagement.testing.Transactions.inline(),
                featureFlagService,
                new com.certmanagement.messaging.transport.TransportProperties(), org.mockito.Mockito.mock(com.certmanagement.service.lifecycle.FeatureLifecycleLock.class),
                com.certmanagement.testing.FeatureFlagResolvers.allEnabled(), discoveryAudit);
        lenient().when(featureFlagService.isEnabled(anyString(), any())).thenReturn(true);
        lenient().when(orgTypeResolver.resolve(org.mockito.ArgumentMatchers.any(Long.class)))
                .thenReturn("B2B");
        lenient().when(discoveryScanService.beginBatch(any(), anyLong()))
                .thenReturn(DiscoveryBatchContext.untracked());
        lenient().when(discoveryConfigRepository.findByOrganizationIdAndTargetTypeAndCredentialXrefForUpdate(
                        anyLong(), anyString(), anyString()))
                .thenReturn(List.of());
        lenient().when(discoveryConfigRepository.save(any(DiscoveryConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(discoveredCertObservationRepository
                        .findCredentialXrefsByDiscoveredCertIdIn(any()))
                .thenReturn(List.of());
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
    }

    // ------------------------------------------------------------------ //
    //  triggerDiscovery
    // ------------------------------------------------------------------ //

    @Test
    void triggerDiscovery_publishesCommandWithCorrectFields() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        DiscoveryRunResponse response = service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        ArgumentCaptor<CertDiscoveryCommand> captor = ArgumentCaptor.forClass(CertDiscoveryCommand.class);
        verify(certAgentPublisher).publishDiscoveryCommand(captor.capture());

        CertDiscoveryCommand command = captor.getValue();
        assertThat(command.getOrganizationId()).isEqualTo(ORG_ID.toString());
        assertThat(command.getTargetType()).isEqualTo(TARGET_TYPE);
        assertThat(command.getDeploymentCredHandle()).isEqualTo(KV_PATH);
        assertThat(command.getCredentialScopeJson()).isEqualTo(SCOPE_JSON);
        assertThat(command.getRequestId()).isNotBlank();
        assertThat(response.getRequestId()).isEqualTo(command.getRequestId());
        assertThat(response.getStatus()).isEqualTo("STARTED");
        assertThat(response.getMessage()).isEqualTo("Discovery has started. Results will appear shortly.");
    }

    @Test
    void triggerDiscovery_usesSuppliedCorrelationIdForDiscoveryTrace() {
        GatewayRequestContext.set(1, ORG_ID.toString(), "req-frontend-123", "admin@example.com");
        GatewayRequestContext.setCorrelationId("corr-frontend-123");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        ArgumentCaptor<CertDiscoveryCommand> captor = ArgumentCaptor.forClass(CertDiscoveryCommand.class);
        verify(certAgentPublisher).publishDiscoveryCommand(captor.capture());
        CertDiscoveryCommand command = captor.getValue();
        assertThat(command.getCorrelationId()).isEqualTo("corr-frontend-123");
        assertThat(command.getRequestId()).startsWith("req-");
        assertThat(command.getRequestId().substring("req-".length()))
                .matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        assertThat(command.getRequestId()).hasSizeLessThanOrEqualTo(100);
    }

    @Test
    void triggerDiscovery_credentialNotFound_throwsBadRequest() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("could not find");

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerDiscovery_credentialBelongsToDifferentOrg_throwsBadRequest() {
        CredentialReferenceEntity cred = buildCredential();
        cred.setOrganizationId(99L); // different org
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF))
                .isInstanceOf(BadRequestException.class);

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerDiscovery_credentialHasNoKvPath_throwsBadRequest() {
        CredentialReferenceEntity cred = buildCredential();
        cred.setSecretHandle(null);
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("no KV path");

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerDiscovery_kubernetesTranslatesAuthMethodToAuthProvider() throws Exception {
        CredentialReferenceEntity cred = buildCredential(
                "KUBERNETES_SECRETS",
                KV_PATH,
                "{\"authMethod\":\"AZURE\",\"clusterName\":\"prod-aks\",\"namespaces\":[\"payments\",\"frontend\",\"frontend\"]}");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        service.triggerDiscovery(ORG_ID, "KUBERNETES_SECRETS", CRED_XREF);

        ArgumentCaptor<CertDiscoveryCommand> captor = ArgumentCaptor.forClass(CertDiscoveryCommand.class);
        verify(certAgentPublisher).publishDiscoveryCommand(captor.capture());
        CertDiscoveryCommand command = captor.getValue();
        assertThat(command.getTargetType()).isEqualTo("KUBERNETES_SECRETS");
        assertThat(command.getDeploymentCredHandle()).isEqualTo(KV_PATH);
        assertThat(objectMapper.readTree(command.getCredentialScopeJson()))
                .isEqualTo(objectMapper.readTree(
                        "{\"authProvider\":\"AZURE\",\"clusterName\":\"prod-aks\",\"namespaces\":[\"frontend\",\"payments\"]}"));
        assertThat(command.getCredentialScopeJson()).doesNotContain("authMethod");
    }

    @Test
    void triggerDiscovery_normalizesTargetTypeBeforeDispatch() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        service.triggerDiscovery(ORG_ID, " aws_acm ", CRED_XREF);

        ArgumentCaptor<CertDiscoveryCommand> captor = ArgumentCaptor.forClass(CertDiscoveryCommand.class);
        verify(certAgentPublisher).publishDiscoveryCommand(captor.capture());
        assertThat(captor.getValue().getTargetType()).isEqualTo("AWS_ACM");
        verify(discoveryScanService).createScan(
                any(), eq(ORG_ID), eq("AWS_ACM"), eq(CRED_XREF), any(), any());
    }

    @Test
    void triggerDiscovery_looksUpMatchingConfigsWithoutRequiringUniqueness() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        verify(discoveryConfigRepository)
                .findByOrganizationIdAndTargetTypeAndCredentialXrefForUpdate(ORG_ID, TARGET_TYPE, CRED_XREF);
    }

    @Test
    void triggerDiscovery_duplicateMatchingConfigsReusesNewestResultWithoutFailing() {
        DiscoveryConfigEntity newestConfig = savedConfig();
        newestConfig.setId(20L);
        DiscoveryConfigEntity olderConfig = savedConfig();
        olderConfig.setId(10L);
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));
        when(discoveryConfigRepository.findByOrganizationIdAndTargetTypeAndCredentialXrefForUpdate(
                ORG_ID, TARGET_TYPE, CRED_XREF))
                .thenReturn(List.of(newestConfig, olderConfig));

        DiscoveryRunResponse response = service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        assertThat(response.getConfigId()).isEqualTo(20L);
        verify(discoveryConfigRepository, never()).save(olderConfig);
    }

    @Test
    void triggerDiscovery_blankTargetTypeIsRejected() {
        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, " ", CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("targetType");

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    /** Targets the agent has no adapter for are refused with 400 before anything is stored or sent. */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"AZURE_APP_GW", "AZURE_AFD", "AZURE_APP_GW_CONTAINERS",
            "GCP_CERT_MANAGER", "GCP_ALB", "GCP_PROXY_NLB", "GCP_API_GW", "GCP_CLOUD_CDN"})
    void triggerDiscovery_unsupportedTargetsAre400(String targetType) {
        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, targetType, CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Discovery is not available for " + targetType)
                .hasMessageContaining("AWS_ACM").hasMessageContaining("KUBERNETES_SECRETS");

        verify(discoveryConfigRepository, never()).save(any());
        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    /** The AWS types that only repeat the ACM region listing point at AWS ACM (region) discovery. */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"AWS_ALB", "AWS_NLB", "AWS_CLOUDFRONT",
            "AWS_API_GW_REST", "AWS_API_GW_HTTP", "aws_alb"})
    void triggerDiscovery_awsAcmAliasesAre400WithTheAcmHint(String targetType) {
        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, targetType, CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("use AWS ACM (region) discovery; it covers certificates attached to "
                        + "ALB, NLB, CloudFront and API Gateway");

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void theSupportedTargetsAreExactlyWhatTheAgentDiscovers() {
        assertThat(DiscoveryCredentialPolicy.DISCOVERABLE_TARGETS)
                .containsExactlyInAnyOrder("AWS_ACM", "AWS_ORGANIZATION", "AZURE_KV", "KUBERNETES_SECRETS");
        for (String target : DiscoveryCredentialPolicy.DISCOVERABLE_TARGETS) {
            assertThat(DiscoveryCredentialPolicy.unsupportedTargetReason(target)).isNull();
        }
        assertThat(DiscoveryCredentialPolicy.unsupportedTargetReason("SOMETHING_ELSE")).contains("Unknown");
    }

    @Test
    void triggerDiscovery_kubernetesSaIncluster_allowsNullKvPathForB2b() {
        CredentialReferenceEntity cred = buildCredential(
                "KUBERNETES_SECRETS",
                null,
                "{\"authMethod\":\"SA_INCLUSTER\",\"clusterName\":\"prod-aks\",\"namespaces\":[\"frontend\"]}");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        service.triggerDiscovery(ORG_ID, "KUBERNETES_SECRETS", CRED_XREF);

        ArgumentCaptor<CertDiscoveryCommand> captor = ArgumentCaptor.forClass(CertDiscoveryCommand.class);
        verify(certAgentPublisher).publishDiscoveryCommand(captor.capture());
        assertThat(captor.getValue().getDeploymentCredHandle()).isNull();
    }

    @Test
    void triggerDiscovery_kubernetesRejectsInvalidNamespaceScope() {
        CredentialReferenceEntity cred = buildCredential(
                "KUBERNETES_SECRETS",
                KV_PATH,
                "{\"authMethod\":\"AZURE\",\"clusterName\":\"prod-aks\",\"namespaces\":\"frontend\"}");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, "KUBERNETES_SECRETS", CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("all_namespaces");
    }

    @Test
    void triggerDiscovery_kubernetesRejectsEmptyNamespaceScope() {
        CredentialReferenceEntity cred = buildCredential(
                "KUBERNETES_SECRETS",
                KV_PATH,
                "{\"authMethod\":\"AZURE\",\"clusterName\":\"prod-aks\",\"namespaces\":[]}");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, "KUBERNETES_SECRETS", CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must not be empty");
    }

    @Test
    void triggerDiscovery_kubernetesRejectsUnknownAuthMethod() {
        CredentialReferenceEntity cred = buildCredential(
                "KUBERNETES_SECRETS",
                KV_PATH,
                "{\"authMethod\":\"KUBECONFIG\",\"clusterName\":\"prod-aks\",\"namespaces\":[\"frontend\"]}");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, "KUBERNETES_SECRETS", CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("authMethod");
    }

    @Test
    void triggerDiscovery_allowsSecretBackedCredential() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));
        when(orgTypeResolver.resolve(ORG_ID)).thenReturn("B2B");

        service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        verify(certAgentPublisher).publishDiscoveryCommand(any());
    }

    @Test
    void triggerDiscovery_publishFailureReturnsFriendlyFailedStatus() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));
        doThrow(new RuntimeException("message queue unavailable"))
                .when(certAgentPublisher).publishDiscoveryCommand(any());

        DiscoveryRunResponse response = service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.FAILED.name());
        assertThat(response.getMessage()).isEqualTo("Discovery could not be started. Please try again.");
        verify(discoveryScanService).markDispatchFailed(response.getRequestId());
    }

    @Test
    void triggerSavedDiscovery_unknownConfigReturnsNotFound() {
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(100L, ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.triggerSavedDiscovery(ORG_ID, 100L))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Discovery configuration not found");

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerSavedDiscovery_inProgressReturnsStatusWithoutPublishingDuplicate() {
        DiscoveryConfigEntity config = savedConfig();
        config.setStatus(DiscoveryConfigStatus.IN_PROGRESS);
        config.setLastRequestId("req-existing");
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-existing"))
                .thenReturn(Optional.of(DiscoveryScanStatus.RECEIVING));

        DiscoveryRunResponse response = service.triggerSavedDiscovery(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.IN_PROGRESS.name());
        assertThat(response.getMessage()).contains("still running");
        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerSavedDiscovery_inactiveSavedCredentialReturnsCredentialInvalid() {
        DiscoveryConfigEntity config = savedConfig();
        CredentialReferenceEntity credential = buildCredential();
        credential.setStatus("DELETED");
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(credential));

        DiscoveryRunResponse response = service.triggerSavedDiscovery(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.CREDENTIAL_INVALID.name());
        assertThat(response.getMessage()).contains("no longer active");
        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerSavedDiscovery_readySavedConfigPublishesWithSavedCredential() {
        DiscoveryConfigEntity config = savedConfig();
        config.setStatus(DiscoveryConfigStatus.READY);
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        DiscoveryRunResponse response = service.triggerSavedDiscovery(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.STARTED.name());
        assertThat(response.getCredentialXref()).isEqualTo(CRED_XREF);
        verify(certAgentPublisher).publishDiscoveryCommand(any());
    }

    @Test
    void triggerSavedDiscovery_completeConfigPublishesNewRun() {
        DiscoveryConfigEntity config = savedConfig();
        config.setStatus(DiscoveryConfigStatus.COMPLETE);
        config.setLastRequestId("req-existing-complete");
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-existing-complete"))
                .thenReturn(Optional.empty());
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        DiscoveryRunResponse response = service.triggerSavedDiscovery(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.STARTED.name());
        assertThat(response.getRequestId()).isNotEqualTo("req-existing-complete");
        verify(certAgentPublisher).publishDiscoveryCommand(any());
    }

    @Test
    void triggerSavedDiscovery_completeScanStatusStillPublishesNewRun() {
        DiscoveryConfigEntity config = savedConfig();
        config.setStatus(DiscoveryConfigStatus.COMPLETE);
        config.setLastRequestId("req-existing-complete");
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-existing-complete"))
                .thenReturn(Optional.of(DiscoveryScanStatus.COMPLETE));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        DiscoveryRunResponse response = service.triggerSavedDiscovery(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.STARTED.name());
        assertThat(response.getRequestId()).isNotEqualTo("req-existing-complete");
        verify(certAgentPublisher).publishDiscoveryCommand(any());
    }

    @Test
    void triggerSavedDiscovery_invalidSavedProviderReturnsCredentialInvalid() {
        DiscoveryConfigEntity config = savedConfig();
        CredentialReferenceEntity credential = buildCredential();
        credential.setProvider("AZURE_KEY_VAULT");
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(credential));

        DiscoveryRunResponse response = service.triggerSavedDiscovery(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.CREDENTIAL_INVALID.name());
        assertThat(response.getMessage()).contains("no longer usable");
        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerAllSavedDiscovery_dispatchesEveryNonActiveConfigAndKeepsActiveStatus() {
        DiscoveryConfigEntity activeConfig = savedConfig();
        activeConfig.setId(10L);
        activeConfig.setLastRequestId("req-active");
        activeConfig.setStatus(DiscoveryConfigStatus.IN_PROGRESS);

        DiscoveryConfigEntity completeConfig = savedConfig();
        completeConfig.setId(11L);
        completeConfig.setLastRequestId("req-complete");
        completeConfig.setStatus(DiscoveryConfigStatus.COMPLETE);

        when(discoveryConfigRepository.findAllByOrganizationIdForUpdate(ORG_ID))
                .thenReturn(List.of(activeConfig, completeConfig));
        when(discoveryScanService.findStatus("req-active"))
                .thenReturn(Optional.of(DiscoveryScanStatus.DISPATCHED));
        when(discoveryScanService.findStatus("req-complete"))
                .thenReturn(Optional.empty());
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        List<DiscoveryRunResponse> responses = service.triggerAllSavedDiscovery(ORG_ID);

        assertThat(responses).hasSize(2);
        assertThat(responses.get(0).getStatus()).isEqualTo(DiscoveryConfigStatus.IN_PROGRESS.name());
        assertThat(responses.get(1).getStatus()).isEqualTo(DiscoveryConfigStatus.STARTED.name());
        verify(certAgentPublisher, times(1)).publishDiscoveryCommand(any());
    }

    @Test
    void triggerAllSavedDiscovery_dispatchesTerminalCompleteAndFailedConfigs() {
        DiscoveryConfigEntity completeConfig = savedConfig();
        completeConfig.setId(10L);
        completeConfig.setStatus(DiscoveryConfigStatus.COMPLETE);
        completeConfig.setLastRequestId("req-complete");
        DiscoveryConfigEntity failedConfig = savedConfig();
        failedConfig.setId(11L);
        failedConfig.setStatus(DiscoveryConfigStatus.FAILED);
        failedConfig.setLastRequestId("req-failed");

        when(discoveryConfigRepository.findAllByOrganizationIdForUpdate(ORG_ID))
                .thenReturn(List.of(completeConfig, failedConfig));
        when(discoveryScanService.findStatus("req-complete"))
                .thenReturn(Optional.of(DiscoveryScanStatus.COMPLETE));
        when(discoveryScanService.findStatus("req-failed"))
                .thenReturn(Optional.of(DiscoveryScanStatus.FAILED));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        List<DiscoveryRunResponse> responses = service.triggerAllSavedDiscovery(ORG_ID);

        assertThat(responses).extracting(DiscoveryRunResponse::getStatus)
                .containsExactly(DiscoveryConfigStatus.STARTED.name(), DiscoveryConfigStatus.STARTED.name());
        verify(certAgentPublisher, times(2)).publishDiscoveryCommand(any());
    }

    @Test
    void triggerAllSavedDiscovery_invalidCredentialDoesNotBlockOtherConfigs() {
        DiscoveryConfigEntity invalidConfig = savedConfig();
        invalidConfig.setId(10L);
        invalidConfig.setCredentialXref("cred-invalid");
        DiscoveryConfigEntity validConfig = savedConfig();
        validConfig.setId(11L);

        CredentialReferenceEntity invalidCredential = buildCredential();
        invalidCredential.setCredentialXref("cred-invalid");
        invalidCredential.setProvider("AZURE_KEY_VAULT");

        when(discoveryConfigRepository.findAllByOrganizationIdForUpdate(ORG_ID))
                .thenReturn(List.of(invalidConfig, validConfig));
        when(credentialReferenceRepository.findByCredentialXref("cred-invalid"))
                .thenReturn(Optional.of(invalidCredential));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        List<DiscoveryRunResponse> responses = service.triggerAllSavedDiscovery(ORG_ID);

        assertThat(responses).extracting(DiscoveryRunResponse::getStatus)
                .containsExactly(DiscoveryConfigStatus.CREDENTIAL_INVALID.name(), DiscoveryConfigStatus.STARTED.name());
        verify(certAgentPublisher, times(1)).publishDiscoveryCommand(any());
    }

    /**
     * Bulk: a run of every saved configuration records a started row for each one that ran and a failure row for
     * each one that did not, explicitly; the request itself succeeds, so nothing else would record them.
     */
    @Test
    void triggerAllSavedDiscovery_recordsEachConfigurationsOutcome() {
        DiscoveryConfigEntity gone = savedConfig();
        gone.setId(9L);
        gone.setCredentialXref("cred-deleted");
        DiscoveryConfigEntity invalidConfig = savedConfig();
        invalidConfig.setId(10L);
        invalidConfig.setCredentialXref("cred-invalid");
        DiscoveryConfigEntity validConfig = savedConfig();
        validConfig.setId(11L);
        CredentialReferenceEntity invalidCredential = buildCredential();
        invalidCredential.setCredentialXref("cred-invalid");
        invalidCredential.setProvider("AZURE_KEY_VAULT");
        when(discoveryConfigRepository.findAllByOrganizationIdForUpdate(ORG_ID))
                .thenReturn(List.of(gone, invalidConfig, validConfig));
        when(credentialReferenceRepository.findByCredentialXref("cred-deleted")).thenReturn(Optional.empty());
        when(credentialReferenceRepository.findByCredentialXref("cred-invalid"))
                .thenReturn(Optional.of(invalidCredential));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        service.triggerAllSavedDiscovery(ORG_ID);

        verify(discoveryAudit).scanNotStarted(gone, DiscoveryAuditRecorder.Trigger.ALL_SAVED,
                AuditReason.of("CREDENTIAL_NOT_ACTIVE"));
        verify(discoveryAudit).scanNotStarted(invalidConfig, DiscoveryAuditRecorder.Trigger.ALL_SAVED,
                AuditReason.of("CREDENTIAL_DETAILS_INVALID"));
        ArgumentCaptor<CertDiscoveryCommand> command = ArgumentCaptor.forClass(CertDiscoveryCommand.class);
        verify(certAgentPublisher).publishDiscoveryCommand(command.capture());
        verify(discoveryAudit).scanStarted(eq(validConfig), any(CredentialReferenceEntity.class),
                eq(command.getValue().getRequestId()), eq(DiscoveryAuditRecorder.Trigger.ALL_SAVED));
        org.mockito.Mockito.verifyNoMoreInteractions(discoveryAudit);
    }

    @Test
    void triggerDiscovery_recordsTheStartedScanAndASavedRunIsRecordedAsSaved() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        DiscoveryRunResponse response = service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        verify(discoveryAudit).scanStarted(any(DiscoveryConfigEntity.class), any(CredentialReferenceEntity.class),
                eq(response.getRequestId()), eq(DiscoveryAuditRecorder.Trigger.NEW));

        DiscoveryConfigEntity config = savedConfig();
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID)).thenReturn(Optional.of(config));
        DiscoveryRunResponse saved = service.triggerSavedDiscovery(ORG_ID, 10L);
        verify(discoveryAudit).scanStarted(eq(config), any(CredentialReferenceEntity.class),
                eq(saved.getRequestId()), eq(DiscoveryAuditRecorder.Trigger.SAVED));
    }

    @Test
    void aScanThatFailsValidationRecordsNoStartedRow() {
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF))
                .isInstanceOf(BadRequestException.class);
        org.mockito.Mockito.verifyNoInteractions(discoveryAudit);
    }

    @Test
    void triggerAllSavedDiscovery_mintsDistinctUuidRequestIdsForEachDispatch() {
        DiscoveryConfigEntity awsConfig = savedConfig();
        awsConfig.setId(10L);
        DiscoveryConfigEntity secondAwsConfig = savedConfig();
        secondAwsConfig.setId(11L);

        when(discoveryConfigRepository.findAllByOrganizationIdForUpdate(ORG_ID))
                .thenReturn(List.of(awsConfig, secondAwsConfig));
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(buildCredential()));

        service.triggerAllSavedDiscovery(ORG_ID);

        ArgumentCaptor<CertDiscoveryCommand> captor = ArgumentCaptor.forClass(CertDiscoveryCommand.class);
        verify(certAgentPublisher, times(2)).publishDiscoveryCommand(captor.capture());
        assertThat(captor.getAllValues())
                .extracting(CertDiscoveryCommand::getRequestId)
                .allSatisfy(requestId -> assertThat(requestId)
                        .matches("req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
                .doesNotHaveDuplicates();
    }

    @Test
    void deleteDiscoveryConfig_marksConfigSoftDeleted() {
        DiscoveryConfigEntity config = savedConfig();
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID))
                .thenReturn(Optional.of(config));

        service.deleteDiscoveryConfig(ORG_ID, 10L);

        assertThat(config.getIsDeleted()).isTrue();
        assertThat(config.getStatusMessage()).isEqualTo("Discovery configuration was deleted.");
        verify(discoveryConfigRepository).save(config);
        verify(discoveryAudit).configDeleted(config);
    }

    @Test
    void listDiscoveryConfigs_returnsAllConfigsWithRefreshedStatus() {
        DiscoveryConfigEntity awsConfig = savedConfig();
        awsConfig.setId(10L);
        awsConfig.setLastRequestId("req-aws");
        DiscoveryConfigEntity k8sConfig = savedConfig();
        k8sConfig.setId(11L);
        k8sConfig.setTargetType("KUBERNETES_SECRETS");
        k8sConfig.setCredentialXref("cred-k8s-prod");
        k8sConfig.setLastRequestId("req-k8s");
        when(discoveryConfigRepository.findAllByOrganizationIdAndIsDeletedFalseOrderByUpdatedAtDesc(ORG_ID))
                .thenReturn(List.of(k8sConfig, awsConfig));
        when(discoveryScanService.findStatus("req-k8s"))
                .thenReturn(Optional.of(DiscoveryScanStatus.RECEIVING));
        when(discoveryScanService.findStatus("req-aws"))
                .thenReturn(Optional.empty());

        List<DiscoveryRunResponse> responses = service.listDiscoveryConfigs(ORG_ID);

        assertThat(responses).extracting(DiscoveryRunResponse::getConfigId)
                .containsExactly(11L, 10L);
        assertThat(responses.get(0).getStatus()).isEqualTo(DiscoveryConfigStatus.IN_PROGRESS.name());
        assertThat(responses.get(0).getTargetType()).isEqualTo("KUBERNETES_SECRETS");
        assertThat(responses.get(0).getCredentialXref()).isEqualTo("cred-k8s-prod");
        assertThat(responses.get(1).getStatus()).isEqualTo(DiscoveryConfigStatus.READY.name());
    }

    @Test
    void getDiscoveryConfigStatus_usesOrganizationScopedConfigId() {
        DiscoveryConfigEntity config = savedConfig();
        config.setLastRequestId("req-existing");
        when(discoveryConfigRepository.findByIdAndOrganizationIdAndIsDeletedFalse(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-existing"))
                .thenReturn(Optional.of(DiscoveryScanStatus.COMPLETE));

        DiscoveryRunResponse response = service.getDiscoveryConfigStatus(ORG_ID, 10L);

        assertThat(response.getConfigId()).isEqualTo(10L);
        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.COMPLETE.name());
        assertThat(response.getCompletedAt()).isNotNull();
    }

    /** A PARTIAL run says so and lists what it could not read, for the configuration and the list. */
    @Test
    void aPartialRunExposesItsFailedScopes() {
        DiscoveryConfigEntity config = savedConfig();
        config.setLastRequestId("req-partial");
        com.certmanagement.messaging.model.DiscoveryFailedScope failed =
                com.certmanagement.messaging.model.DiscoveryFailedScope.builder()
                        .scopeType("AWS_ACCOUNT").scopeId("111111111111")
                        .errorCode("DISCOVERY_AWS_ASSUME_ROLE_DENIED").message("AccessDenied").build();
        when(discoveryConfigRepository.findByIdAndOrganizationIdAndIsDeletedFalse(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(discoveryConfigRepository.findAllByOrganizationIdAndIsDeletedFalseOrderByUpdatedAtDesc(ORG_ID))
                .thenReturn(List.of(config));
        when(discoveryScanService.findStatus("req-partial")).thenReturn(Optional.of(DiscoveryScanStatus.PARTIAL));
        when(discoveryScanService.findFailedScopes("req-partial")).thenReturn(List.of(failed));

        DiscoveryRunResponse response = service.getDiscoveryConfigStatus(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.PARTIAL.name());
        assertThat(response.getMessage()).contains("could not be read");
        assertThat(response.getFailedScopes()).containsExactly(failed);
        assertThat(service.listDiscoveryConfigs(ORG_ID)).singleElement()
                .satisfies(r -> assertThat(r.getFailedScopes()).extracting(
                        com.certmanagement.messaging.model.DiscoveryFailedScope::getScopeId)
                        .containsExactly("111111111111"));
    }

    @Test
    void aRunWithNoFailedScopesHasAnEmptyList() {
        DiscoveryConfigEntity config = savedConfig();
        config.setLastRequestId(null);
        when(discoveryConfigRepository.findByIdAndOrganizationIdAndIsDeletedFalse(10L, ORG_ID))
                .thenReturn(Optional.of(config));

        assertThat(service.getDiscoveryConfigStatus(ORG_ID, 10L).getFailedScopes()).isEmpty();
    }

    @Test
    void triggerDiscovery_targetTypeMismatchesCredentialProvider_throwsBadRequest() {
        // Credential is for AWS_ACM but caller requests AZURE_KV, so it should be rejected.
        CredentialReferenceEntity cred = buildCredential();
        cred.setProvider("AWS_ACM");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, "AZURE_KV", CRED_XREF))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("AWS_ACM")
                .hasMessageContaining("AZURE_KV");

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    @Test
    void triggerDiscovery_credentialProviderBlank_skipsValidationAndPublishes() {
        // Defensive: legacy credentials without a provider should not break the flow.
        CredentialReferenceEntity cred = buildCredential();
        cred.setProvider("");
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF))
                .thenReturn(Optional.of(cred));

        service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        verify(certAgentPublisher).publishDiscoveryCommand(any());
    }

    // ------------------------------------------------------------------ //
    //  listDiscoveredCerts
    // ------------------------------------------------------------------ //

    @Test
    @SuppressWarnings("unchecked")
    void listDiscoveredCerts_withExpiresWithinDays_queriesRepository() {
        when(discoveredCertRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(Page.empty());

        Pageable pageable = PageRequest.of(0, 20);
        service.listDiscoveredCerts(ORG_ID, null, null, null, null, null, 7, pageable);

        verify(discoveredCertRepository).findAll(any(Specification.class), eq(pageable));
    }

    @Test
    @SuppressWarnings("unchecked")
    void listDiscoveredCerts_managedRow_resolvesCertificateXref() {
        // Discovered serial is ACM colon-hex; the CertPing cert stores it as bare upper-hex.
        // Both normalize to the same value, so the managed row links to that cert's xref.
        DiscoveredCertEntity managed = DiscoveredCertEntity.builder()
                .id(1L).organizationId(ORG_ID).targetType("AWS_ACM")
                .resourceId("arn:aws:acm:us-east-1:123:certificate/abc")
                .serialNumber("0a:00:1a").managed(true).build();
        when(discoveredCertRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(managed)));
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(ORG_ID))
                .thenAnswer(invocation -> Stream.of(serialXref("0A001A", "cert-xyz")));

        var page = service.listDiscoveredCerts(
                ORG_ID, null, null, null, null, null, null, PageRequest.of(0, 20));

        assertThat(page.getContent().get(0).getManagedCertificateXref()).isEqualTo("cert-xyz");
    }

    @Test
    @SuppressWarnings("unchecked")
    void listDiscoveredCerts_unmanagedRow_hasNoXrefAndSkipsLookup() {
        DiscoveredCertEntity external = DiscoveredCertEntity.builder()
                .id(2L).organizationId(ORG_ID).targetType("AWS_ACM")
                .resourceId("arn:aws:acm:us-east-1:123:certificate/ext")
                .serialNumber("0a:00:1a").managed(false).build();
        when(discoveredCertRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(external)));

        var page = service.listDiscoveredCerts(
                ORG_ID, null, null, null, null, null, null, PageRequest.of(0, 20));

        assertThat(page.getContent().get(0).getManagedCertificateXref()).isNull();
        verify(certificateRepository, never()).streamSerialNumberAndXrefByOrganizationId(anyLong());
    }

    @Test
    @SuppressWarnings("unchecked")
    void listDiscoveredCerts_resolvesCredentialXrefFromObservation() {
        DiscoveredCertEntity cert = DiscoveredCertEntity.builder()
                .id(7L).organizationId(ORG_ID).targetType("AWS_ACM")
                .resourceId("arn:aws:acm:us-east-1:123:certificate/obs")
                .serialNumber("0a:00:1a").managed(false).build();
        when(discoveredCertRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(cert)));
        when(discoveredCertObservationRepository.findCredentialXrefsByDiscoveredCertIdIn(any()))
                .thenReturn(List.of(credentialView(7L, "cred-255081270228850")));

        var page = service.listDiscoveredCerts(
                ORG_ID, null, null, null, null, null, null, PageRequest.of(0, 20));

        assertThat(page.getContent().get(0).getCredentialXref()).isEqualTo("cred-255081270228850");
    }

    private static CertificateRepository.SerialXref serialXref(String serial, String xref) {
        return new CertificateRepository.SerialXref() {
            @Override public String getSerialNumber() { return serial; }
            @Override public String getCertificateXref() { return xref; }
        };
    }

    private static DiscoveredCertCredentialView credentialView(Long certId, String credentialXref) {
        return new DiscoveredCertCredentialView() {
            @Override public Long getDiscoveredCertId() { return certId; }
            @Override public String getCredentialXref() { return credentialXref; }
        };
    }

    @Test
    void getDiscoveredCertificate_usesOrganizationScopedLookup() {
        DiscoveredCertEntity entity = DiscoveredCertEntity.builder()
                .id(7L)
                .organizationId(ORG_ID)
                .targetType("AWS_ACM")
                .resourceId("arn:aws:acm:us-east-1:123:certificate/abc")
                .build();
        when(discoveredCertRepository.findByIdAndOrganizationId(7L, ORG_ID))
                .thenReturn(Optional.of(entity));

        var details = service.getDiscoveredCertificate(ORG_ID, 7L);

        assertThat(details.getId()).isEqualTo(7L);
        assertThat(details.getProviderData()).isNull();
        assertThat(details.getInventoryStatus()).isEqualTo("UNKNOWN");
    }

    @Test
    void getDiscoveredCertificate_wrongOrganization_returnsNotFound() {
        when(discoveredCertRepository.findByIdAndOrganizationId(7L, ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getDiscoveredCertificate(ORG_ID, 7L))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ------------------------------------------------------------------ //
    //  persistDiscoveryResults
    // ------------------------------------------------------------------ //

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_successResponse_upsertsEntries() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/abc";
        CertDiscoveryResponse response = buildSuccessResponse(List.of(buildEntry(arn)));

        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of());
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(anyLong()))
                .thenAnswer(invocation -> Stream.empty());

        service.persistDiscoveryResults(response);

        ArgumentCaptor<List<DiscoveredCertEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(discoveredCertRepository).saveAll(captor.capture());
        assertThat(captor.getValue()).hasSize(1);
        assertThat(captor.getValue().get(0).getResourceId()).isEqualTo(arn);
        assertThat(captor.getValue().get(0).getProviderData()).isNull();
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_kubernetesData_deserializesAndPersists() throws Exception {
        String payload = """
                {
                  "requestId": "req-k8s-001",
                  "organizationId": "42",
                  "targetType": "KUBERNETES_SECRETS",
                  "status": "SUCCESS",
                  "discoveredCerts": [
                    {
                      "resourceId": "k8s://prod/frontend/secrets/api-tls",
                      "domain": "api.example.com",
                      "serialNumber": "0a:00:1a",
                      "kubernetesData": {
                        "clusterName": "prod",
                        "usageComplete": true,
                        "impact": {"summary": "used by ingress"}
                      }
                    }
                  ]
                }
                """;
        CertDiscoveryResponse response = objectMapper.readValue(payload, CertDiscoveryResponse.class);

        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of());
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(anyLong()))
                .thenAnswer(invocation -> Stream.empty());

        service.persistDiscoveryResults(response);

        ArgumentCaptor<List<DiscoveredCertEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(discoveredCertRepository).saveAll(captor.capture());
        assertThat(captor.getValue().get(0).getProviderData())
                .isEqualTo(objectMapper.readTree(
                        "{\"clusterName\":\"prod\",\"usageComplete\":true,\"impact\":{\"summary\":\"used by ingress\"}}"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_managedCert_setsManagedTrue() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/managed";
        // buildEntry sets serialNumber="0a:00:1a" (ACM colon-hex). The managed cert stores
        // it in the issuance format "0A001A" (upper-case hex, no separators). Both must
        // normalize to the same canonical value for the match to succeed.
        CertDiscoveryResponse response = buildSuccessResponse(List.of(buildEntry(arn)));

        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of());
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(anyLong()))
                .thenAnswer(invocation -> Stream.of(serialXref("0A001A", "cert-managed")));

        service.persistDiscoveryResults(response);

        ArgumentCaptor<List<DiscoveredCertEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(discoveredCertRepository).saveAll(captor.capture());
        assertThat(captor.getValue().get(0).getManaged()).isTrue();
    }

    @Test
    void persistDiscoveryResults_invalidKubernetesData_rejectsWholeBatch() throws Exception {
        DiscoveredCertEntry entry = buildEntry("k8s://prod/frontend/secrets/api-tls");
        entry.setKubernetesData(objectMapper.readTree("{\"clusterName\":\"prod\"}"));
        CertDiscoveryResponse response = buildSuccessResponse(List.of(entry));
        response.setTargetType("KUBERNETES_SECRETS");
        when(kubernetesDataValidator.validateAndConvert(entry.getKubernetesData()))
                .thenThrow(new IllegalArgumentException("Invalid Kubernetes discovery response"));

        assertThatThrownBy(() -> service.persistDiscoveryResults(response))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid Kubernetes discovery response");

        verify(discoveredCertRepository, never()).saveAll(any());
        verify(discoveryScanService, never()).completeBatch(any(), anyInt());
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_trackedBatch_recordsObservationAndCompletion() {
        DiscoveredCertEntry entry = buildEntry("arn:aws:acm:us-east-1:123:certificate/tracked");
        CertDiscoveryResponse response = buildSuccessResponse(List.of(entry));
        DiscoveryBatchContext context = new DiscoveryBatchContext(true, false, "scope-1", CRED_XREF);
        when(discoveryScanService.beginBatch(response, ORG_ID)).thenReturn(context);
        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of());
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(anyLong()))
                .thenAnswer(invocation -> Stream.empty());
        when(discoveredCertRepository.saveAll(anyList())).thenAnswer(invocation -> {
            List<DiscoveredCertEntity> certificates = invocation.getArgument(0);
            certificates.getFirst().setId(9L);
            return certificates;
        });

        service.persistDiscoveryResults(response);

        verify(discoveryScanService).recordObservations(
                eq(context), eq("req-001"), eq(ORG_ID), eq("AWS_ACM"), anyList(), any());
        verify(discoveryScanService).completeBatch(response, 1);
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_serialMismatch_setsManagedFalse() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/external";
        CertDiscoveryResponse response = buildSuccessResponse(List.of(buildEntry(arn)));

        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of());
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(anyLong()))
                .thenAnswer(invocation -> Stream.of(serialXref("DEADBEEF", "cert-managed")));

        service.persistDiscoveryResults(response);

        ArgumentCaptor<List<DiscoveredCertEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(discoveredCertRepository).saveAll(captor.capture());
        assertThat(captor.getValue().get(0).getManaged()).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_noSerial_setsManagedNull() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/no-serial";
        DiscoveredCertEntry entry = buildEntry(arn);
        entry.setSerialNumber(null);   // source reported no serial / agent could not parse it
        CertDiscoveryResponse response = buildSuccessResponse(List.of(entry));

        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of());

        service.persistDiscoveryResults(response);

        ArgumentCaptor<List<DiscoveredCertEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(discoveredCertRepository).saveAll(captor.capture());
        assertThat(captor.getValue().get(0).getManaged()).isNull();
        verify(certificateRepository, never()).streamSerialNumberAndXrefByOrganizationId(anyLong());
    }

    @Test
    void normalizeSerial_canonicalizesAcrossFormats() {
        // Colon-separated lower-case hex (ACM) and bare upper-case hex (issuance) match.
        assertThat(DiscoveryService.normalizeSerial("0a:00:1a"))
                .isEqualTo(DiscoveryService.normalizeSerial("0A001A"));
        // Leading zeros are stripped; null/blank/non-hex collapse to empty.
        assertThat(DiscoveryService.normalizeSerial("00FF")).isEqualTo("FF");
        assertThat(DiscoveryService.normalizeSerial(null)).isEmpty();
        assertThat(DiscoveryService.normalizeSerial("  ")).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_existingEntry_updatesInPlace() {
        String arn = "arn:aws:acm:us-east-1:123:certificate/abc";
        DiscoveredCertEntity existing = DiscoveredCertEntity.builder()
                .id(1L)
                .organizationId(ORG_ID)
                .resourceId(arn)
                .targetType("AWS_ACM")
                .requestId("old-req")
                .build();

        CertDiscoveryResponse response = buildSuccessResponse(List.of(buildEntry(arn)));

        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of(existing));
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(anyLong()))
                .thenAnswer(invocation -> Stream.empty());

        service.persistDiscoveryResults(response);

        ArgumentCaptor<List<DiscoveredCertEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(discoveredCertRepository).saveAll(captor.capture());
        assertThat(captor.getValue()).containsExactly(existing);
        assertThat(existing.getRequestId()).isNotEqualTo("old-req");
    }

    @Test
    @SuppressWarnings("unchecked")
    void persistDiscoveryResults_existingEntry_updatesKubernetesData() throws Exception {
        String resourceId = "k8s://prod/frontend/secrets/api-tls";
        DiscoveredCertEntity existing = DiscoveredCertEntity.builder()
                .id(1L)
                .organizationId(ORG_ID)
                .resourceId(resourceId)
                .targetType("KUBERNETES_SECRETS")
                .requestId("old-req")
                .providerData(objectMapper.readTree("{\"clusterName\":\"old\"}"))
                .build();
        DiscoveredCertEntry entry = buildEntry(resourceId);
        entry.setKubernetesData(objectMapper.readTree("{\"clusterName\":\"prod\",\"usageComplete\":true}"));
        CertDiscoveryResponse response = buildSuccessResponse(List.of(entry));
        response.setTargetType("KUBERNETES_SECRETS");

        when(discoveredCertRepository.findAllByOrganizationIdAndResourceIdIn(anyLong(), anyList()))
                .thenReturn(List.of(existing));
        when(certificateRepository.streamSerialNumberAndXrefByOrganizationId(anyLong()))
                .thenAnswer(invocation -> Stream.empty());

        service.persistDiscoveryResults(response);

        ArgumentCaptor<List<DiscoveredCertEntity>> captor = ArgumentCaptor.forClass(List.class);
        verify(discoveredCertRepository).saveAll(captor.capture());
        assertThat(captor.getValue()).containsExactly(existing);
        assertThat(existing.getProviderData())
                .isEqualTo(objectMapper.readTree("{\"clusterName\":\"prod\",\"usageComplete\":true}"));
    }

    @Test
    void persistDiscoveryResults_failedResponse_doesNotPersist() {
        CertDiscoveryResponse response = new CertDiscoveryResponse();
        response.setRequestId("req-001");
        response.setOrganizationId(ORG_ID.toString());
        response.setTargetType(TARGET_TYPE);
        response.setStatus("FAILED");
        response.setErrorCode("DISCOVERY_ACM_ACCESS_DENIED");

        service.persistDiscoveryResults(response);

        verify(discoveredCertRepository, never()).saveAll(any());
    }

    @Test
    void persistDiscoveryResults_emptyList_doesNotPersist() {
        CertDiscoveryResponse response = buildSuccessResponse(List.of());

        service.persistDiscoveryResults(response);

        verify(discoveredCertRepository, never()).saveAll(any());
    }

    @Test
    void persistDiscoveryResults_whenBatchFinalizesScanMarksConfigComplete() {
        CertDiscoveryResponse response = buildSuccessResponse(List.of());
        DiscoveryConfigEntity config = savedConfig();
        config.setStatus(DiscoveryConfigStatus.STARTED);
        config.setLastRequestId("req-001");
        when(discoveryConfigRepository.findByLastRequestIdAndOrganizationIdAndIsDeletedFalse("req-001", ORG_ID))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-001"))
                .thenReturn(Optional.of(DiscoveryScanStatus.COMPLETE));

        service.persistDiscoveryResults(response);

        assertThat(config.getStatus()).isEqualTo(DiscoveryConfigStatus.COMPLETE);
        assertThat(config.getLastCompletedAt()).isNotNull();
    }

    @Test
    void persistDiscoveryResults_malformedOrganizationId_dropsBatchWithoutThrowing() {
        // Agent should never send this, but if it does we must not throw. Otherwise
        // the queue worker would retry a poison message forever.
        CertDiscoveryResponse response = buildSuccessResponse(
                List.of(buildEntry("arn:aws:acm:us-east-1:123:certificate/abc")));
        response.setOrganizationId("not-a-number");

        service.persistDiscoveryResults(response);

        verify(discoveredCertRepository, never()).saveAll(any());
    }

    @Test
    void persistDiscoveryResults_missingRequestId_rejectsBatch() {
        CertDiscoveryResponse response = buildSuccessResponse(
                List.of(buildEntry("arn:aws:acm:us-east-1:123:certificate/abc")));
        response.setRequestId(null);

        assertThatThrownBy(() -> service.persistDiscoveryResults(response))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestId");
    }

    @Test
    void persistDiscoveryResults_nullOrganizationId_dropsBatchWithoutThrowing() {
        CertDiscoveryResponse response = buildSuccessResponse(
                List.of(buildEntry("arn:aws:acm:us-east-1:123:certificate/abc")));
        response.setOrganizationId(null);

        service.persistDiscoveryResults(response);

        verify(discoveredCertRepository, never()).saveAll(any());
    }

    @Test
    void markDiscoveryAgentFailed_marksScanAndConfigFailedWithFriendlyMessage() {
        DiscoveryConfigEntity config = savedConfig();
        config.setStatus(DiscoveryConfigStatus.IN_PROGRESS);
        config.setStatusMessage("Discovery is still running. Results will appear shortly.");
        config.setLastRequestId("req-001");
        when(discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse("req-001"))
                .thenReturn(Optional.of(config));

        service.markDiscoveryAgentFailed(
                "req-001",
                "DISCOVERY_K8S_SECRET_LIST_FAILED",
                "list Kubernetes Secrets for discovery namespace=team-a failed (HTTP 403)");

        verify(discoveryScanService).markAgentFailed("req-001", null, "DISCOVERY_K8S_SECRET_LIST_FAILED");
        assertThat(config.getStatus()).isEqualTo(DiscoveryConfigStatus.FAILED);
        assertThat(config.getStatusMessage())
                .isEqualTo("Discovery failed because Kubernetes denied access to list Secrets in namespace team-a. Check the service account RBAC and try again.");
        assertThat(config.getLastCompletedAt()).isNotNull();
    }

    @Test
    void getDiscoveryConfigStatus_failedScanPreservesSpecificFailureMessage() {
        DiscoveryConfigEntity config = savedConfig();
        config.setStatus(DiscoveryConfigStatus.FAILED);
        config.setStatusMessage("Discovery failed because Kubernetes denied access to list Secrets in namespace team-a. Check the service account RBAC and try again.");
        config.setLastRequestId("req-001");
        when(discoveryConfigRepository.findByIdAndOrganizationIdAndIsDeletedFalse(10L, ORG_ID))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-001"))
                .thenReturn(Optional.of(DiscoveryScanStatus.FAILED));

        DiscoveryRunResponse response = service.getDiscoveryConfigStatus(ORG_ID, 10L);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.FAILED.name());
        assertThat(response.getMessage()).isEqualTo(config.getStatusMessage());
        assertThat(response.getCompletedAt()).isNotNull();
        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
    }

    // ------------------------------------------------------------------ //
    //  Helpers
    // ------------------------------------------------------------------ //

    private CredentialReferenceEntity buildCredential() {
        return buildCredential("AWS_ACM", KV_PATH, SCOPE_JSON);
    }

    private CredentialReferenceEntity buildCredential(String provider, String secretHandle, String configJson) {
        return CredentialReferenceEntity.builder()
                .credentialXref(CRED_XREF)
                .organizationId(ORG_ID)
                .provider(provider)
                .type("DEPLOYMENT")
                .secretHandle(secretHandle)
                .configJson(configJson)
                .build();
    }

    private DiscoveryConfigEntity savedConfig() {
        return DiscoveryConfigEntity.builder()
                .id(10L)
                .organizationId(ORG_ID)
                .targetType(TARGET_TYPE)
                .credentialXref(CRED_XREF)
                .status(DiscoveryConfigStatus.READY)
                .statusMessage("Discovery is ready to run.")
                .build();
    }

    private CertDiscoveryResponse buildSuccessResponse(List<DiscoveredCertEntry> entries) {
        CertDiscoveryResponse response = new CertDiscoveryResponse();
        response.setRequestId("req-001");
        response.setOrganizationId(ORG_ID.toString());
        response.setTargetType(TARGET_TYPE);
        response.setStatus("SUCCESS");
        response.setDiscoveredCerts(entries);
        return response;
    }

    private DiscoveredCertEntry buildEntry(String resourceId) {
        DiscoveredCertEntry entry = new DiscoveredCertEntry();
        entry.setResourceId(resourceId);
        entry.setDomain("test.example.net");
        entry.setSubjectDn("CN=test.example.net,O=CertPing Test");
        entry.setSanDomains(List.of("test.example.net"));
        entry.setKeyAlgorithm("RSA-2048");
        entry.setSignatureAlgorithm("SHA256WITHRSA");
        entry.setNotBefore("2026-05-05T21:24:07Z");
        entry.setNotAfter("2026-08-03T21:24:07Z");
        entry.setIssuer("CertPing Test");
        entry.setSerialNumber("0a:00:1a");
        entry.setCertStatus("ISSUED");
        entry.setKeyUsage("DIGITAL_SIGNATURE,KEY_ENCIPHERMENT");
        entry.setExtendedKeyUsage("TLS_WEB_SERVER_AUTHENTICATION");
        entry.setCertType("IMPORTED");
        return entry;
    }
}
