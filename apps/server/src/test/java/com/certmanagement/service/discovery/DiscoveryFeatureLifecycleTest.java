// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.messaging.transport.TransportProperties;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.discovery.DiscoveryRunResponse;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DiscoveryConfigEntity;
import com.certmanagement.entity.DiscoveryConfigStatus;
import com.certmanagement.entity.DiscoveryScanStatus;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DiscoveredCertObservationRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DiscoveryConfigRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.testing.Transactions;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * DISCOVERY as a switchable feature, and the trigger's transaction boundaries: runs are recorded in
 * a short transaction and published after it commits; results for an organization with the feature
 * off are dropped and the scan cancelled; a run whose command expired undelivered stops blocking.
 */
@ExtendWith(MockitoExtension.class)
class DiscoveryFeatureLifecycleTest {

    private static final Long ORG_ID = 42L;
    private static final String CRED_XREF = "cred-aws-acm-001";
    private static final String TARGET_TYPE = "AWS_ACM";

    @Mock private CertAgentPublisher certAgentPublisher;
    @Mock private com.certmanagement.service.FeatureFlagResolver featureFlagResolver;
    @Mock private OrgTypeResolver orgTypeResolver;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;
    @Mock private DiscoveryConfigRepository discoveryConfigRepository;
    @Mock private DiscoveredCertRepository discoveredCertRepository;
    @Mock private DiscoveredCertObservationRepository discoveredCertObservationRepository;
    @Mock private CertificateRepository certificateRepository;
    @Mock private DiscoveryScanService discoveryScanService;
    @Mock private DiscoveryScopeKeyFactory discoveryScopeKeyFactory;
    @Mock private KubernetesDiscoveryDataValidator kubernetesDataValidator;
    @Mock private FeatureFlagService featureFlagService;

    private DiscoveryService service;

    @BeforeEach
    void setUp() {
        service = new DiscoveryService(certAgentPublisher, orgTypeResolver, credentialReferenceRepository,
                discoveryConfigRepository, discoveredCertRepository, discoveredCertObservationRepository,
                certificateRepository, discoveryScanService, discoveryScopeKeyFactory, kubernetesDataValidator,
                new DiscoveryCredentialPolicy(JsonMapper.builderWithJackson2Defaults().build()),
                new DiscoveredCertMapper(), Transactions.inline(), featureFlagService, new TransportProperties(), org.mockito.Mockito.mock(com.certmanagement.service.lifecycle.FeatureLifecycleLock.class),
                featureFlagResolver, org.mockito.Mockito.mock(com.certmanagement.service.audit.DiscoveryAuditRecorder.class));
        lenient().when(orgTypeResolver.resolve(anyLong())).thenReturn("B2B");
        lenient().when(discoveryConfigRepository.save(any(DiscoveryConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(discoveryConfigRepository.findByOrganizationIdAndTargetTypeAndCredentialXrefForUpdate(
                anyLong(), anyString(), anyString())).thenReturn(List.of());
    }

    private void discoveryIs(boolean enabled) {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.DISCOVERY, ORG_ID)).thenReturn(enabled);
        lenient().when(featureFlagResolver.resolveUncached(FeatureFlags.DISCOVERY, ORG_ID)).thenReturn(enabled);
        if (!enabled) {
            lenient().doThrow(new FeatureDisabledException(FeatureFlags.DISCOVERY))
                    .when(featureFlagService).assertEnabled(FeatureFlags.DISCOVERY, ORG_ID);
        }
    }

    private CredentialReferenceEntity credential() {
        return CredentialReferenceEntity.builder()
                .credentialXref(CRED_XREF).organizationId(ORG_ID).provider(TARGET_TYPE).type("DEPLOYMENT")
                .status("ACTIVE").secretHandle("https://kv/secrets/aws")
                .configJson("{\"authMode\":\"STATIC_KEYS\",\"region\":\"us-east-1\"}").build();
    }

    private DiscoveryConfigEntity config(String lastRequestId) {
        return DiscoveryConfigEntity.builder().id(10L).organizationId(ORG_ID).targetType(TARGET_TYPE)
                .credentialXref(CRED_XREF).status(DiscoveryConfigStatus.IN_PROGRESS)
                .statusMessage("Discovery is still running. Results will appear shortly.")
                .lastRequestId(lastRequestId).build();
    }

    // ── triggers ─────────────────────────────────────────────────────────

    @Test
    void trigger_isRefusedWhenDiscoveryIsOffForTheOrg() {
        discoveryIs(false);

        assertThatThrownBy(() -> service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF))
                .isInstanceOf(FeatureDisabledException.class);
        assertThatThrownBy(() -> service.triggerAllSavedDiscovery(ORG_ID))
                .isInstanceOf(FeatureDisabledException.class);
        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
        verify(discoveryScanService, never()).createScan(any(), any(), any(), any(), any(), any());
    }

    @Test
    void trigger_switchedOffAfterTheRunWasRecorded_isCancelledInsteadOfPublished() {
        discoveryIs(true);
        // The switch-off commits after the run's transaction re-checked the flag, before the publish.
        when(featureFlagResolver.resolveUncached(FeatureFlags.DISCOVERY, ORG_ID)).thenReturn(false);
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF)).thenReturn(Optional.of(credential()));
        when(discoveryScanService.markCancelled(anyString(), eq(ORG_ID))).thenReturn(true);
        DiscoveryConfigEntity recorded = config("req-recorded");
        when(discoveryConfigRepository.findByLastRequestIdAndOrganizationIdAndIsDeletedFalse(anyString(), eq(ORG_ID)))
                .thenReturn(Optional.of(recorded));

        DiscoveryRunResponse response = service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        verify(certAgentPublisher, never()).publishDiscoveryCommand(any());
        verify(discoveryScanService).markCancelled(anyString(), eq(ORG_ID));
        assertThat(recorded.getStatus()).isEqualTo(DiscoveryConfigStatus.CANCELLED);
        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.CANCELLED.name());
    }

    @Test
    void trigger_publishesOnlyAfterTheTransactionHasCommitted() {
        discoveryIs(true);
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF)).thenReturn(Optional.of(credential()));
        AtomicBoolean publishedInsideTransaction = new AtomicBoolean(true);
        doAnswer(invocation -> {
            publishedInsideTransaction.set(TransactionSynchronizationManager.isActualTransactionActive());
            return null;
        }).when(certAgentPublisher).publishDiscoveryCommand(any());

        DiscoveryRunResponse response = service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        assertThat(publishedInsideTransaction).isFalse();
        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.STARTED.name());
    }

    @Test
    void trigger_publishFailureIsRecordedOnTheSavedConfiguration() {
        discoveryIs(true);
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF)).thenReturn(Optional.of(credential()));
        when(discoveryConfigRepository.save(any(DiscoveryConfigEntity.class))).thenAnswer(invocation -> {
            DiscoveryConfigEntity saved = invocation.getArgument(0);
            saved.setId(10L);
            return saved;
        });
        doThrow(new RuntimeException("bus down")).when(certAgentPublisher).publishDiscoveryCommand(any());
        when(discoveryConfigRepository.findById(10L)).thenAnswer(invocation -> {
            DiscoveryConfigEntity reloaded = config(null);
            reloaded.setLastRequestId(lastPublishedRequestId());
            return Optional.of(reloaded);
        });

        DiscoveryRunResponse response = service.triggerDiscovery(ORG_ID, TARGET_TYPE, CRED_XREF);

        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.FAILED.name());
        verify(discoveryScanService).markDispatchFailed(response.getRequestId());
    }

    private String lastPublishedRequestId() {
        org.mockito.ArgumentCaptor<String> requestId = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(discoveryScanService).createScan(requestId.capture(), any(), any(), any(), any(), any());
        return requestId.getValue();
    }

    @Test
    void savedTrigger_aRunWhoseCommandExpiredUndeliveredNoLongerBlocksANewRun() {
        discoveryIs(true);
        DiscoveryConfigEntity config = config("req-stale");
        when(discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(10L, ORG_ID)).thenReturn(Optional.of(config));
        when(discoveryScanService.findStatus("req-stale")).thenReturn(Optional.of(DiscoveryScanStatus.DISPATCHED));
        when(discoveryScanService.expireIfUndelivered(eq("req-stale"), any())).thenReturn(true);
        when(credentialReferenceRepository.findByCredentialXref(CRED_XREF)).thenReturn(Optional.of(credential()));

        DiscoveryRunResponse response = service.triggerSavedDiscovery(ORG_ID, 10L);

        verify(certAgentPublisher).publishDiscoveryCommand(any());
        assertThat(response.getStatus()).isEqualTo(DiscoveryConfigStatus.STARTED.name());
    }

    // ── inbound ──────────────────────────────────────────────────────────

    @Test
    void results_forAnOrgWithDiscoveryOff_areDroppedAndTheScanCancelled() {
        discoveryIs(false);
        DiscoveryConfigEntity config = config("req-1");
        when(discoveryScanService.markCancelled("req-1", ORG_ID)).thenReturn(true);
        when(discoveryConfigRepository.findByLastRequestIdAndOrganizationIdAndIsDeletedFalse("req-1", ORG_ID))
                .thenReturn(Optional.of(config));
        CertDiscoveryResponse response = new CertDiscoveryResponse();
        response.setRequestId("req-1");
        response.setOrganizationId(ORG_ID.toString());
        response.setTargetType(TARGET_TYPE);
        response.setStatus("SUCCESS");
        response.setDiscoveredCerts(List.of());

        service.persistDiscoveryResults(response, ORG_ID);

        verify(discoveryScanService, never()).beginBatch(any(), any());
        verify(discoveredCertRepository, never()).saveAll(any());
        assertThat(config.getStatus()).isEqualTo(DiscoveryConfigStatus.CANCELLED);
    }

    @Test
    void lateBatches_forACancelledScan_areIgnoredEvenAfterReEnabling() {
        discoveryIs(true);
        when(discoveryScanService.findStatus("req-1")).thenReturn(Optional.of(DiscoveryScanStatus.CANCELLED));
        CertDiscoveryResponse response = new CertDiscoveryResponse();
        response.setRequestId("req-1");
        response.setOrganizationId(ORG_ID.toString());
        response.setTargetType(TARGET_TYPE);
        response.setStatus("SUCCESS");

        service.persistDiscoveryResults(response, ORG_ID);

        verify(discoveryScanService, never()).beginBatch(any(), any());
    }

    @Test
    void completion_forAnOrgWithDiscoveryOff_cancelsInsteadOfFinalizing() {
        discoveryIs(false);
        DiscoveryCompleteMessage message = new DiscoveryCompleteMessage();
        message.setRequestId("req-1");
        message.setOrganizationId(ORG_ID.toString());
        message.setTargetType(TARGET_TYPE);

        service.markDiscoveryComplete(message);

        verify(discoveryScanService).markCancelled("req-1", ORG_ID);
        verify(discoveryScanService, never()).recordCompletion(any(), any());
    }

    @Test
    void agentError_forAnOrgWithDiscoveryOff_cancelsInsteadOfFailing() {
        discoveryIs(false);

        service.markDiscoveryAgentFailed("req-1", ORG_ID, "DISCOVERY_X", "detail");

        verify(discoveryScanService).markCancelled("req-1", ORG_ID);
        verify(discoveryScanService, never()).markAgentFailed(any(), any());
    }
}
