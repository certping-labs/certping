// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.entity.DiscoveryScanEntity;
import com.certmanagement.entity.DiscoveryScanStatus;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.repository.DiscoveredCertObservationRepository;
import com.certmanagement.repository.DiscoveryScanRepository;
import com.certmanagement.service.audit.DiscoveryAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryScanServiceTest {

    @Mock private DiscoveryScanRepository scanRepository;
    @Mock private DiscoveredCertObservationRepository observationRepository;
    @Mock private DiscoveryReconciliationService reconciliationService;
    @Mock private DiscoveryAuditRecorder discoveryAudit;

    private DiscoveryScanService service;

    @BeforeEach
    void setUp() {
        service = new DiscoveryScanService(scanRepository, observationRepository, reconciliationService, discoveryAudit);
    }

    @Test
    void beginBatch_identifiesDuplicateWithoutCountingItAgain() {
        DiscoveryScanEntity scan = scan(new Integer[]{0}, 1, 1);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        DiscoveryBatchContext context = service.beginBatch(response(0, 1), 42L);

        assertThat(context.duplicate()).isTrue();
        service.completeBatch(response(0, 1), 1);
        assertThat(scan.getReceivedCertCount()).isEqualTo(1);
    }

    @Test
    void recordCompletion_waitsForAllBatches() {
        DiscoveryScanEntity scan = scan(new Integer[]{0}, 2, 1);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.recordCompletion(completion(2), 42L);

        assertThat(scan.isCompletionReceived()).isTrue();
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.RECEIVING);
        verify(observationRepository, never()).findAllByScopeKey(any());
    }

    @Test
    void completionAndLastBatch_finalizeExactScopeAndRetireOldScope() {
        DiscoveryScanEntity scan = scan(new Integer[]{0}, 2, 1);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.recordCompletion(completion(2), 42L);
        service.completeBatch(response(1, 2), 1);

        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.COMPLETE);
        verify(reconciliationService).reconcile(any(), any());
    }

    @Test
    void zeroCertificateCompletion_finalizesWithoutResultBatches() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.recordCompletion(completion(0), 42L);

        assertThat(scan.getExpectedBatches()).isZero();
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.COMPLETE);
        verify(reconciliationService).reconcile(any(), any());
    }

    /** A scan whose batches or completion name failed scopes ends PARTIAL and reconciles around them. */
    @Test
    @SuppressWarnings("unchecked")
    void failedScopesFromBatchesAndCompletionFinalizeAsPartial() {
        DiscoveryScanEntity scan = scan(new Integer[0], 2, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));
        CertDiscoveryResponse first = response(0, 2);
        first.setFailedScopes(List.of(failed("K8S_NAMESPACE", "payments")));
        CertDiscoveryResponse second = response(1, 2);
        second.setFailedScopes(List.of(failed("K8S_NAMESPACE", "payments")));
        DiscoveryCompleteMessage completion = completion(2);
        completion.setFailedScopes(List.of(failed("K8S_NAMESPACE", "payments"), failed("K8S_NAMESPACE", "billing")));

        service.completeBatch(first, 1);
        service.recordCompletion(completion, 42L);
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.RECEIVING);
        service.completeBatch(second, 1);

        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.PARTIAL);
        org.mockito.ArgumentCaptor<List<com.certmanagement.messaging.model.DiscoveryFailedScope>> scopes =
                org.mockito.ArgumentCaptor.forClass(List.class);
        verify(reconciliationService).reconcile(org.mockito.ArgumentMatchers.eq(scan), any(), scopes.capture());
        verify(reconciliationService, never()).reconcile(any(), any());
        assertThat(scopes.getValue()).extracting(com.certmanagement.messaging.model.DiscoveryFailedScope::getScopeId)
                .containsExactly("payments", "billing");
        verify(discoveryAudit).scanCompleted(scan);

        // A redelivered batch after the scan finished changes nothing.
        service.completeBatch(second, 1);
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.PARTIAL);
    }

    @Test
    void findFailedScopesReadsTheStoredList() {
        DiscoveryScanEntity scan = scan(new Integer[0], 0, 0);
        scan.setFailedScopes(FailedScopes.toJson(List.of(failed("K8S_NAMESPACE", "payments"))));
        when(scanRepository.findById("req-1")).thenReturn(Optional.of(scan));
        when(scanRepository.findById("req-none")).thenReturn(Optional.empty());

        assertThat(service.findFailedScopes("req-1")).singleElement().satisfies(s -> {
            assertThat(s.getScopeType()).isEqualTo("K8S_NAMESPACE");
            assertThat(s.getScopeId()).isEqualTo("payments");
            assertThat(s.getErrorCode()).isEqualTo("DISCOVERY_K8S_SECRET_LIST_FAILED");
            assertThat(s.getMessage()).isEqualTo("HTTP 403");
        });
        assertThat(service.findFailedScopes("req-none")).isEmpty();
        assertThat(service.findFailedScopes(" ")).isEmpty();
    }

    @Test
    void anEmptyFailedScopeListStillCompletes() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));
        DiscoveryCompleteMessage completion = completion(0);
        completion.setFailedScopes(List.of());

        service.recordCompletion(completion, 42L);

        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.COMPLETE);
        assertThat(scan.getFailedScopes()).isNull();
    }

    private static com.certmanagement.messaging.model.DiscoveryFailedScope failed(String type, String id) {
        return com.certmanagement.messaging.model.DiscoveryFailedScope.builder()
                .scopeType(type).scopeId(id).errorCode("DISCOVERY_K8S_SECRET_LIST_FAILED").message("HTTP 403").build();
    }

    @Test
    void completionWithMismatchedTotal_doesNotFinalize() {
        DiscoveryScanEntity scan = scan(new Integer[]{0}, 1, 1);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.recordCompletion(completion(2), 42L);

        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.RECEIVING);
        verify(observationRepository, never()).findAllByScopeKey(any());
    }

    @Test
    void beginBatch_rejectsCrossOrganizationResponse() {
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan(new Integer[0], 1, 0)));

        assertThatThrownBy(() -> service.beginBatch(response(0, 1), 99L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identity does not match");
    }

    @Test
    void recordObservations_batchLoadsAndCreatesScopeObservations() {
        DiscoveredCertEntity certificate = DiscoveredCertEntity.builder().id(9L).build();
        DiscoveryBatchContext context = new DiscoveryBatchContext(true, false, "scope-1", "cred-1");
        when(observationRepository.findAllByDiscoveredCertIdInAndScopeKey(List.of(9L), "scope-1"))
                .thenReturn(List.of());

        service.recordObservations(
                context,
                "req-1",
                42L,
                "AWS_ACM",
                List.of(certificate),
                OffsetDateTime.parse("2026-06-24T08:00:00Z"));

        verify(observationRepository).findAllByDiscoveredCertIdInAndScopeKey(List.of(9L), "scope-1");
        verify(observationRepository).saveAll(any());
    }

    @Test
    void recordObservations_emptyTrackedBatchDoesNotQueryObservationTable() {
        DiscoveryBatchContext context = new DiscoveryBatchContext(true, false, "scope-1", "cred-1");

        service.recordObservations(
                context,
                "req-1",
                42L,
                "AWS_ACM",
                List.of(),
                OffsetDateTime.parse("2026-06-24T08:00:00Z"));

        verify(observationRepository, never()).findAllByDiscoveredCertIdInAndScopeKey(any(), any());
        verify(observationRepository, never()).saveAll(any());
    }

    // ── cancellation and undelivered expiry ─────────────────────────────

    @Test
    void markCancelled_endsARunningScanForItsOwnOrg() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        assertThat(service.markCancelled("req-1", 42L)).isTrue();

        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.CANCELLED);
        assertThat(scan.getFinalizedAt()).isNotNull();
    }

    @Test
    void markCancelled_refusesAnotherOrgsScanAndLeavesFinishedScansAlone() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        assertThat(service.markCancelled("req-1", 99L)).isFalse();
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.RECEIVING);

        scan.setStatus(DiscoveryScanStatus.COMPLETE);
        assertThat(service.markCancelled("req-1", 42L)).isFalse();
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.COMPLETE);
    }

    @Test
    void cancelledScan_ignoresLateCompletionAndBatches() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        scan.setStatus(DiscoveryScanStatus.CANCELLED);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.recordCompletion(completion(0), 42L);
        service.completeBatch(response(0, 1), 1);

        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.CANCELLED);
        assertThat(scan.isCompletionReceived()).isFalse();
        verify(reconciliationService, never()).reconcile(any(), any());
    }

    @Test
    void expireIfUndelivered_failsOnlyOldDispatchedScans() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        scan.setStatus(DiscoveryScanStatus.DISPATCHED);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        assertThat(service.expireIfUndelivered("req-1", scan.getRequestedAt().minusMinutes(1))).isFalse();
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.DISPATCHED);

        assertThat(service.expireIfUndelivered("req-1", scan.getRequestedAt().plusMinutes(1))).isTrue();
        assertThat(scan.getStatus()).isEqualTo(DiscoveryScanStatus.FAILED);
    }

    // ── What became of a scan, as CertPing's audit rows ──────────────────

    @Test
    void aFinalizedScanRecordsItsCompletionOnce() {
        DiscoveryScanEntity scan = scan(new Integer[]{0}, 2, 1);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.recordCompletion(completion(2), 42L);
        verifyNoInteractions(discoveryAudit);
        service.completeBatch(response(1, 2), 1);
        service.recordCompletion(completion(2), 42L);

        verify(discoveryAudit).scanCompleted(scan);
        org.mockito.Mockito.verifyNoMoreInteractions(discoveryAudit);
    }

    @Test
    void anAgentFailureRecordsItsCodeOnceAndARedeliveryNothingMore() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.markAgentFailed("req-1", 42L, "DISCOVERY_ACM_ACCESS_DENIED");
        service.markAgentFailed("req-1", 42L, "DISCOVERY_ACM_ACCESS_DENIED");

        verify(discoveryAudit).scanFailed(scan, com.certmanagement.audit.AuditReason.of("DISCOVERY_ACM_ACCESS_DENIED"));
        org.mockito.Mockito.verifyNoMoreInteractions(discoveryAudit);
    }

    @Test
    void anotherOrganizationsFailureRecordsNothing() {
        DiscoveryScanEntity scan = scan(new Integer[0], null, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(scan));

        service.markAgentFailed("req-1", 99L, "DISCOVERY_ACM_ACCESS_DENIED");

        verifyNoInteractions(discoveryAudit);
    }

    @Test
    void aCancelledExpiredOrUnsentScanIsRecorded() {
        DiscoveryScanEntity running = scan(new Integer[0], null, 0);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(running));
        assertThat(service.markCancelled("req-1", 42L)).isTrue();
        assertThat(service.markCancelled("req-1", 42L)).isFalse();
        verify(discoveryAudit).scanCancelled(running);

        DiscoveryScanEntity dispatched = scan(new Integer[0], null, 0);
        dispatched.setStatus(DiscoveryScanStatus.DISPATCHED);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(dispatched));
        service.expireIfUndelivered("req-1", dispatched.getRequestedAt().plusMinutes(1));
        verify(discoveryAudit).scanFailed(dispatched, DiscoveryAuditRecorder.NOT_PICKED_UP);

        DiscoveryScanEntity unsent = scan(new Integer[0], null, 0);
        unsent.setStatus(DiscoveryScanStatus.DISPATCHED);
        when(scanRepository.findByRequestIdForUpdate("req-1")).thenReturn(Optional.of(unsent));
        service.markDispatchFailed("req-1");
        verify(discoveryAudit).scanFailed(unsent, DiscoveryAuditRecorder.NOT_SENT);
        org.mockito.Mockito.verifyNoMoreInteractions(discoveryAudit);
    }

    private DiscoveryScanEntity scan(Integer[] batches, Integer expectedBatches, int receivedCertCount) {
        return DiscoveryScanEntity.builder()
                .requestId("req-1")
                .organizationId(42L)
                .targetType("KUBERNETES_SECRETS")
                .credentialXref("cred-1")
                .scopeKey("scope-1")
                .status(DiscoveryScanStatus.RECEIVING)
                .expectedBatches(expectedBatches)
                .receivedBatchIndices(batches)
                .receivedCertCount(receivedCertCount)
                .requestedAt(OffsetDateTime.parse("2026-06-24T08:00:00Z"))
                .build();
    }

    private CertDiscoveryResponse response(int batchIndex, int totalBatches) {
        CertDiscoveryResponse response = new CertDiscoveryResponse();
        response.setRequestId("req-1");
        response.setOrganizationId("42");
        response.setTargetType("KUBERNETES_SECRETS");
        response.setBatchIndex(batchIndex);
        response.setTotalBatches(totalBatches);
        return response;
    }

    private DiscoveryCompleteMessage completion(int totalCerts) {
        DiscoveryCompleteMessage message = new DiscoveryCompleteMessage();
        message.setRequestId("req-1");
        message.setOrganizationId("42");
        message.setTargetType("KUBERNETES_SECRETS");
        message.setTotalCerts(totalCerts);
        message.setCompletedAt("2026-06-24T08:01:00Z");
        return message;
    }

}
