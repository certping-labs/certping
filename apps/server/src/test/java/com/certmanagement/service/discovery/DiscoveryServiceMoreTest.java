// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.certmanagement.entity.DiscoveryConfigEntity;
import com.certmanagement.entity.DiscoveryConfigStatus;
import com.certmanagement.entity.DiscoveryScanStatus;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DiscoveryConfigRepository;
import com.certmanagement.service.OrgTypeResolver;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DiscoveryServiceMoreTest {

    @Mock private com.certmanagement.service.FeatureFlagService featureFlagService;
    @Mock private CertAgentPublisher certAgentPublisher;
    @Mock private OrgTypeResolver orgTypeResolver;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;
    @Mock private DiscoveryConfigRepository discoveryConfigRepository;
    @Mock private DiscoveredCertRepository discoveredCertRepository;
    @Mock private com.certmanagement.repository.DiscoveredCertObservationRepository discoveredCertObservationRepository;
    @Mock private CertificateRepository certificateRepository;
    @Mock private DiscoveryScanService discoveryScanService;
    @Mock private DiscoveryScopeKeyFactory discoveryScopeKeyFactory;
    @Mock private KubernetesDiscoveryDataValidator kubernetesDataValidator;

    private DiscoveryService service;

    @BeforeEach
    void setUp() {
        service = new DiscoveryService(
                certAgentPublisher, orgTypeResolver, credentialReferenceRepository,
                discoveryConfigRepository, discoveredCertRepository, discoveredCertObservationRepository,
                certificateRepository,
                discoveryScanService, discoveryScopeKeyFactory, kubernetesDataValidator,
                new DiscoveryCredentialPolicy(JsonMapper.builderWithJackson2Defaults().build()),
                new DiscoveredCertMapper(),
                com.certmanagement.testing.Transactions.inline(),
                featureFlagService,
                new com.certmanagement.messaging.transport.TransportProperties(), org.mockito.Mockito.mock(com.certmanagement.service.lifecycle.FeatureLifecycleLock.class),
                com.certmanagement.testing.FeatureFlagResolvers.allEnabled(), org.mockito.Mockito.mock(com.certmanagement.service.audit.DiscoveryAuditRecorder.class));
        org.mockito.Mockito.lenient().when(featureFlagService.isEnabled(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(true);
        lenient().when(discoveryConfigRepository.save(any(DiscoveryConfigEntity.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    private DiscoveryCompleteMessage completeMessage(String orgId) {
        DiscoveryCompleteMessage m = new DiscoveryCompleteMessage();
        m.setRequestId("req-1");
        m.setOrganizationId(orgId);
        m.setTargetType("AWS_ACM");
        m.setTotalCerts(3);
        return m;
    }

    @Test
    void markDiscoveryComplete_recordsCompletion_andSetsConfigComplete() {
        DiscoveryConfigEntity config = DiscoveryConfigEntity.builder()
                .organizationId(42L).targetType("AWS_ACM").credentialXref("x")
                .status(DiscoveryConfigStatus.IN_PROGRESS).build();
        when(discoveryConfigRepository.findByLastRequestIdAndOrganizationIdAndIsDeletedFalse("req-1", 42L))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-1"))
                .thenReturn(Optional.of(DiscoveryScanStatus.COMPLETE));

        service.markDiscoveryComplete(completeMessage("42"));

        verify(discoveryScanService).recordCompletion(any(), eq(42L));
        assertThat(config.getStatus()).isEqualTo(DiscoveryConfigStatus.COMPLETE);
        assertThat(config.getLastCompletedAt()).isNotNull();
    }

    @Test
    void markDiscoveryComplete_scanNotComplete_leavesConfigStatus() {
        DiscoveryConfigEntity config = DiscoveryConfigEntity.builder()
                .organizationId(42L).targetType("AWS_ACM").credentialXref("x")
                .status(DiscoveryConfigStatus.IN_PROGRESS).build();
        when(discoveryConfigRepository.findByLastRequestIdAndOrganizationIdAndIsDeletedFalse("req-1", 42L))
                .thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-1"))
                .thenReturn(Optional.of(DiscoveryScanStatus.RECEIVING));

        service.markDiscoveryComplete(completeMessage("42"));

        assertThat(config.getStatus()).isEqualTo(DiscoveryConfigStatus.IN_PROGRESS);
    }

    @Test
    void markDiscoveryComplete_nonNumericOrg_throws() {
        assertThatThrownBy(() -> service.markDiscoveryComplete(completeMessage("abc")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be numeric");
    }

    @Test
    void markDiscoveryComplete_blankRequestId_throws() {
        DiscoveryCompleteMessage m = completeMessage("42");
        m.setRequestId("  ");
        assertThatThrownBy(() -> service.markDiscoveryComplete(m))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestId must not be blank");
    }

    @Test
    void markDiscoveryAgentFailed_k8sSecretListForbidden_explainsRbac() {
        DiscoveryConfigEntity config = configWithStatus(DiscoveryConfigStatus.STARTED);
        when(discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse("req-1"))
                .thenReturn(Optional.of(config));

        service.markDiscoveryAgentFailed("req-1",
                "DISCOVERY_K8S_SECRET_LIST_FAILED", "HTTP 403 namespace=prod denied");

        verify(discoveryScanService).markAgentFailed("req-1", null, "DISCOVERY_K8S_SECRET_LIST_FAILED");
        assertThat(config.getStatus()).isEqualTo(DiscoveryConfigStatus.FAILED);
        assertThat(config.getStatusMessage())
                .contains("denied access to list Secrets")
                .contains("namespace prod");
    }

    @Test
    void markDiscoveryAgentFailed_k8sSecretListNoNamespace_usesGenericScope() {
        DiscoveryConfigEntity config = configWithStatus(DiscoveryConfigStatus.STARTED);
        when(discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse("req-1"))
                .thenReturn(Optional.of(config));

        service.markDiscoveryAgentFailed("req-1",
                "DISCOVERY_K8S_SECRET_LIST_FAILED", "could not list secrets");

        assertThat(config.getStatusMessage())
                .contains("the selected namespace")
                .contains("Check the service account permissions");
    }

    @Test
    void markDiscoveryAgentFailed_genericK8sError() {
        DiscoveryConfigEntity config = configWithStatus(DiscoveryConfigStatus.STARTED);
        when(discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse("req-1"))
                .thenReturn(Optional.of(config));

        service.markDiscoveryAgentFailed("req-1", "DISCOVERY_K8S_OTHER", "boom");

        assertThat(config.getStatusMessage()).contains("reading Kubernetes resources");
    }

    @Test
    void markDiscoveryAgentFailed_genericDiscoveryError() {
        DiscoveryConfigEntity config = configWithStatus(DiscoveryConfigStatus.STARTED);
        when(discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse("req-1"))
                .thenReturn(Optional.of(config));

        service.markDiscoveryAgentFailed("req-1", "DISCOVERY_TIMEOUT", "boom");

        assertThat(config.getStatusMessage()).contains("selected credential permissions");
    }

    @Test
    void markDiscoveryAgentFailed_unknownErrorCode_andNullDetail_fallsBackToGeneric() {
        DiscoveryConfigEntity config = configWithStatus(DiscoveryConfigStatus.STARTED);
        when(discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse("req-1"))
                .thenReturn(Optional.of(config));

        service.markDiscoveryAgentFailed("req-1", null, null);

        assertThat(config.getStatusMessage()).isEqualTo("Discovery failed. Please try again.");
    }

    @Test
    void markDiscoveryAgentFailed_noConfigForRequestId_stillMarksScan() {
        when(discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse("req-1"))
                .thenReturn(Optional.empty());

        service.markDiscoveryAgentFailed("req-1", "DISCOVERY_TIMEOUT", "boom");

        verify(discoveryScanService).markAgentFailed("req-1", null, "DISCOVERY_TIMEOUT");
    }

    private DiscoveryConfigEntity configWithStatus(DiscoveryConfigStatus status) {
        return DiscoveryConfigEntity.builder()
                .organizationId(42L).targetType("AWS_ACM").credentialXref("x")
                .status(status).build();
    }
}
