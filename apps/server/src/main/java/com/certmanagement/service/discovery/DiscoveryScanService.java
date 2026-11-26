// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.entity.DiscoveredCertObservationEntity;
import com.certmanagement.entity.DiscoveryObservationStatus;
import com.certmanagement.entity.DiscoveryScanEntity;
import com.certmanagement.entity.DiscoveryScanStatus;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.messaging.model.DiscoveryFailedScope;
import com.certmanagement.repository.DiscoveredCertObservationRepository;
import com.certmanagement.repository.DiscoveryScanRepository;
import com.certmanagement.service.audit.DiscoveryAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class DiscoveryScanService {

    private final DiscoveryScanRepository scanRepository;
    private final DiscoveredCertObservationRepository observationRepository;
    private final DiscoveryReconciliationService reconciliationService;
    /** CertPing's rows for what became of a scan, written with the scan's state change. */
    private final DiscoveryAuditRecorder discoveryAudit;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entityManager;

    @Transactional
    public void createScan(
            String requestId,
            Long organizationId,
            String targetType,
            String credentialXref,
            String scopeKey,
            OffsetDateTime requestedAt) {
        scanRepository.save(DiscoveryScanEntity.builder()
                .requestId(requestId)
                .organizationId(organizationId)
                .targetType(targetType)
                .credentialXref(credentialXref)
                .scopeKey(scopeKey)
                .status(DiscoveryScanStatus.DISPATCHED)
                .receivedBatchIndices(new Integer[0])
                .requestedAt(requestedAt)
                .build());
    }

    @Transactional
    public void markDispatchFailed(String requestId) {
        lockScan(requestId).ifPresent(scan -> {
            boolean wasRunning = !isTerminal(scan.getStatus());
            scan.setStatus(DiscoveryScanStatus.FAILED);
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            scan.setCompletedAt(now);
            scan.setFinalizedAt(now);
            scanRepository.save(scan);
            if (wasRunning) {
                discoveryAudit.scanFailed(scan, DiscoveryAuditRecorder.NOT_SENT);
            }
        });
    }

    /**
     * @deprecated A validly signed message can name another organization's requestId; callers on
     * the agent-message path must use {@link #markAgentFailed(String, Long)} so the scan's org is
     * checked before it is mutated.
     */
    @Deprecated
    @Transactional
    public void markAgentFailed(String requestId) {
        lockScan(requestId).ifPresent(scan -> fail(scan, null));
    }

    /**
     * Marks a scan failed, scoped to the authenticated organization. The success path already
     * checks this via {@code validateBatchIdentity}/{@code recordCompletion}; the failure path has
     * no equivalent gate, so a signed message could otherwise flip another organization's scan to
     * FAILED by naming its requestId. A mismatch is a security event: log it and leave the scan
     * untouched rather than exposing whether the requestId exists to the wrong organization.
     */
    @Transactional
    public void markAgentFailed(String requestId, Long organizationId) {
        markAgentFailed(requestId, organizationId, null);
    }

    /**
     * {@link #markAgentFailed(String, Long)} with the agent's error code, which the scan's failure row is stored
     * with ({@link DiscoveryAuditRecorder#agentReason}); a redelivered failure of a scan already ended records
     * nothing more.
     */
    @Transactional
    public void markAgentFailed(String requestId, Long organizationId, String errorCode) {
        lockScan(requestId).ifPresent(scan -> {
            if (organizationId != null && !organizationId.equals(scan.getOrganizationId())) {
                log.error("SECURITY: agent message from organizationId={} referenced discovery "
                                + "requestId={} owned by a different organization — refusing to mark it failed",
                        organizationId, requestId);
                return;
            }
            fail(scan, errorCode);
        });
    }

    private void fail(DiscoveryScanEntity scan, String errorCode) {
        boolean wasRunning = !isTerminal(scan.getStatus());
        scan.setStatus(DiscoveryScanStatus.FAILED);
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        scan.setCompletedAt(now);
        scan.setFinalizedAt(now);
        scanRepository.save(scan);
        if (wasRunning) {
            discoveryAudit.scanFailed(scan, DiscoveryAuditRecorder.agentReason(errorCode));
        }
    }

    /**
     * Ends a scan without results because {@code DISCOVERY} is off for its organization. Scoped to
     * the authenticated organization like {@link #markAgentFailed(String, Long)}; a scan already in
     * a terminal state is left alone.
     *
     * @return {@code true} when the scan moved to CANCELLED
     */
    @Transactional
    public boolean markCancelled(String requestId, Long organizationId) {
        return lockScan(requestId)
                .filter(scan -> {
                    if (organizationId != null && !organizationId.equals(scan.getOrganizationId())) {
                        log.error("SECURITY: agent message from organizationId={} referenced discovery "
                                        + "requestId={} owned by a different organization — refusing to cancel it",
                                organizationId, requestId);
                        return false;
                    }
                    return !isTerminal(scan.getStatus());
                })
                .map(scan -> {
                    finish(scan, DiscoveryScanStatus.CANCELLED);
                    discoveryAudit.scanCancelled(scan);
                    return true;
                })
                .orElse(false);
    }

    /**
     * Fails a scan whose command can no longer be delivered: still DISPATCHED (no batch arrived)
     * and requested before {@code dispatchedBefore}, i.e. its message queue time-to-live has lapsed. Without
     * this the scan would stay running forever and block the configuration from being run again.
     *
     * @return {@code true} when the scan was expired by this call
     */
    @Transactional
    public boolean expireIfUndelivered(String requestId, OffsetDateTime dispatchedBefore) {
        if (requestId == null || requestId.isBlank()) {
            return false;
        }
        return lockScan(requestId)
                .filter(scan -> scan.getStatus() == DiscoveryScanStatus.DISPATCHED
                        && scan.getRequestedAt() != null
                        && scan.getRequestedAt().isBefore(dispatchedBefore))
                .map(scan -> {
                    finish(scan, DiscoveryScanStatus.FAILED);
                    discoveryAudit.scanFailed(scan, DiscoveryAuditRecorder.NOT_PICKED_UP);
                    log.warn("Discovery scan requestId={} expired undelivered (requestedAt={})",
                            requestId, scan.getRequestedAt());
                    return true;
                })
                .orElse(false);
    }

    private static boolean isTerminal(DiscoveryScanStatus status) {
        return isFinished(status)
                || status == DiscoveryScanStatus.FAILED
                || status == DiscoveryScanStatus.CANCELLED;
    }

    /** Finalized with results: COMPLETE, or PARTIAL when some scopes could not be read. */
    public static boolean isFinished(DiscoveryScanStatus status) {
        return status == DiscoveryScanStatus.COMPLETE || status == DiscoveryScanStatus.PARTIAL;
    }

    /** Adds the scopes a batch or the completion reported to those the scan already holds. */
    private static void addFailedScopes(DiscoveryScanEntity scan, List<DiscoveryFailedScope> reported) {
        if (reported == null || reported.isEmpty()) {
            return;
        }
        scan.setFailedScopes(FailedScopes.toJson(
                FailedScopes.merge(FailedScopes.fromJson(scan.getFailedScopes()), reported)));
    }

    private void finish(DiscoveryScanEntity scan, DiscoveryScanStatus status) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        scan.setStatus(status);
        scan.setCompletedAt(now);
        scan.setFinalizedAt(now);
        scanRepository.save(scan);
    }

    /**
     * Locks the scan row and makes sure the entity reflects it. An earlier plain read in the same
     * transaction (for example the cancelled check before a batch) leaves a managed copy that a
     * {@code FOR UPDATE} query does not refresh; writing that copy back would erase a completion
     * another transaction committed meanwhile, leaving the scan stuck as running.
     */
    private Optional<DiscoveryScanEntity> lockScan(String requestId) {
        Optional<DiscoveryScanEntity> scan = scanRepository.findByRequestIdForUpdate(requestId);
        if (entityManager != null) {
            scan.ifPresent(locked -> {
                entityManager.flush();
                entityManager.refresh(locked);
            });
        }
        return scan;
    }

    @Transactional(readOnly = true)
    public Optional<DiscoveryScanStatus> findStatus(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return Optional.empty();
        }
        return scanRepository.findById(requestId).map(DiscoveryScanEntity::getStatus);
    }

    /** The scopes the scan could not read, from discovery_scan.failed_scopes; empty for none or no scan. */
    @Transactional(readOnly = true)
    public List<DiscoveryFailedScope> findFailedScopes(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return List.of();
        }
        return scanRepository.findById(requestId)
                .map(scan -> FailedScopes.fromJson(scan.getFailedScopes()))
                .orElse(List.of());
    }

    @Transactional
    public DiscoveryBatchContext beginBatch(CertDiscoveryResponse response, Long organizationId) {
        DiscoveryScanEntity scan = lockScan(response.getRequestId())
                .orElse(null);
        if (scan == null) {
            log.warn("Untracked discovery response requestId={}; persisting without reconciliation",
                    response.getRequestId());
            return DiscoveryBatchContext.untracked();
        }

        validateBatchIdentity(scan, response, organizationId);
        validateBatchBounds(response);
        if (scan.getExpectedBatches() == null) {
            scan.setExpectedBatches(response.getTotalBatches());
        } else if (scan.getExpectedBatches() != response.getTotalBatches()) {
            throw new IllegalArgumentException("Discovery totalBatches changed for requestId=" + response.getRequestId());
        }

        boolean duplicate = Arrays.asList(scan.getReceivedBatchIndices()).contains(response.getBatchIndex());
        return new DiscoveryBatchContext(true, duplicate, scan.getScopeKey(), scan.getCredentialXref());
    }

    @Transactional
    public void recordObservations(
            DiscoveryBatchContext context,
            String requestId,
            Long organizationId,
            String targetType,
            Collection<DiscoveredCertEntity> certificates,
            OffsetDateTime observedAt) {
        if (!context.tracked()) {
            return;
        }
        if (certificates.isEmpty()) {
            return;
        }
        List<Long> certificateIds = certificates.stream()
                .map(DiscoveredCertEntity::getId)
                .toList();
        if (certificateIds.stream().anyMatch(java.util.Objects::isNull)) {
            throw new IllegalStateException("Discovered certificate must be persisted before observation");
        }
        Map<Long, DiscoveredCertObservationEntity> existingByCertificateId = observationRepository
                .findAllByDiscoveredCertIdInAndScopeKey(certificateIds, context.scopeKey())
                .stream()
                .collect(Collectors.toMap(
                        DiscoveredCertObservationEntity::getDiscoveredCertId, Function.identity()));
        List<DiscoveredCertObservationEntity> observations = new ArrayList<>(certificates.size());
        for (DiscoveredCertEntity certificate : certificates) {
            DiscoveredCertObservationEntity observation = existingByCertificateId.get(certificate.getId());
            if (observation == null) {
                observation = newObservation(
                        certificate.getId(), organizationId, targetType, context, requestId, observedAt);
            }
            observation.setStatus(DiscoveryObservationStatus.PRESENT);
            observation.setLastSeenRequestId(requestId);
            observation.setLastSeenAt(observedAt);
            observation.setMissingSince(null);
            observations.add(observation);
        }
        if (!observations.isEmpty()) {
            observationRepository.saveAll(observations);
        }
    }

    @Transactional
    public void completeBatch(CertDiscoveryResponse response, int certificateCount) {
        DiscoveryScanEntity scan = lockScan(response.getRequestId())
                .orElse(null);
        if (scan == null || isFinished(scan.getStatus())
                || scan.getStatus() == DiscoveryScanStatus.CANCELLED) {
            return;
        }
        validateBatchBounds(response);
        Set<Integer> received = new HashSet<>(Arrays.asList(scan.getReceivedBatchIndices()));
        if (!received.add(response.getBatchIndex())) {
            return;
        }
        addFailedScopes(scan, response.getFailedScopes());
        scan.setReceivedBatchIndices(received.stream().sorted().toArray(Integer[]::new));
        scan.setReceivedCertCount(scan.getReceivedCertCount() + certificateCount);
        scan.setStatus(DiscoveryScanStatus.RECEIVING);
        scanRepository.save(scan);
        finalizeIfReady(scan);
    }

    @Transactional
    public void recordCompletion(DiscoveryCompleteMessage message, Long organizationId) {
        DiscoveryScanEntity scan = lockScan(message.getRequestId())
                .orElse(null);
        if (scan == null) {
            log.warn("Untracked discovery completion requestId={}; reconciliation skipped", message.getRequestId());
            return;
        }
        if (isFinished(scan.getStatus()) || scan.getStatus() == DiscoveryScanStatus.CANCELLED) {
            return;
        }
        if (!scan.getOrganizationId().equals(organizationId)
                || !scan.getTargetType().equals(message.getTargetType())) {
            throw new IllegalArgumentException("Discovery completion identity does not match requestId="
                    + message.getRequestId());
        }
        if (message.getTotalCerts() < 0) {
            throw new IllegalArgumentException("Discovery totalCerts must not be negative");
        }
        if (message.getTotalCerts() == 0 && scan.getExpectedBatches() == null) {
            scan.setExpectedBatches(0);
        }
        scan.setCompletionReceived(true);
        addFailedScopes(scan, message.getFailedScopes());
        scan.setReportedTotalCerts(message.getTotalCerts());
        scan.setCompletedAt(parseTimestamp(message.getCompletedAt()));
        scanRepository.save(scan);
        finalizeIfReady(scan);
    }

    private void finalizeIfReady(DiscoveryScanEntity scan) {
        if (!isReadyToFinalize(scan)) {
            return;
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        List<DiscoveryFailedScope> failedScopes = FailedScopes.fromJson(scan.getFailedScopes());
        if (failedScopes.isEmpty()) {
            reconciliationService.reconcile(scan, now);
            scan.setStatus(DiscoveryScanStatus.COMPLETE);
        } else {
            // What the agent could not read is not gone; those certificates keep their status.
            reconciliationService.reconcile(scan, now, failedScopes);
            scan.setStatus(DiscoveryScanStatus.PARTIAL);
        }
        scan.setFinalizedAt(now);
        scanRepository.save(scan);
        discoveryAudit.scanCompleted(scan);
        log.info("Finalized discovery scan requestId={}, organizationId={}, targetType={}, certificates={}, "
                        + "status={}, failedScopes={}",
                scan.getRequestId(), scan.getOrganizationId(), scan.getTargetType(), scan.getReportedTotalCerts(),
                scan.getStatus(), failedScopes.size());
    }

    private boolean isReadyToFinalize(DiscoveryScanEntity scan) {
        if (!scan.isCompletionReceived() || scan.getExpectedBatches() == null
                || scan.getReportedTotalCerts() == null) {
            return false;
        }
        Set<Integer> received = new HashSet<>(Arrays.asList(scan.getReceivedBatchIndices()));
        if (received.size() != scan.getExpectedBatches()) {
            return false;
        }
        for (int batchIndex = 0; batchIndex < scan.getExpectedBatches(); batchIndex++) {
            if (!received.contains(batchIndex)) {
                return false;
            }
        }
        if (scan.getReceivedCertCount() != scan.getReportedTotalCerts()) {
            log.warn("Discovery scan requestId={} awaits matching certificate totals: received={}, reported={}",
                    scan.getRequestId(), scan.getReceivedCertCount(), scan.getReportedTotalCerts());
            return false;
        }
        return true;
    }

    private DiscoveredCertObservationEntity newObservation(
            Long certificateId,
            Long organizationId,
            String targetType,
            DiscoveryBatchContext context,
            String requestId,
            OffsetDateTime observedAt) {
        return DiscoveredCertObservationEntity.builder()
                .discoveredCertId(certificateId)
                .organizationId(organizationId)
                .targetType(targetType)
                .credentialXref(context.credentialXref())
                .scopeKey(context.scopeKey())
                .status(DiscoveryObservationStatus.PRESENT)
                .lastSeenRequestId(requestId)
                .firstSeenAt(observedAt)
                .lastSeenAt(observedAt)
                .build();
    }

    private void validateBatchIdentity(
            DiscoveryScanEntity scan, CertDiscoveryResponse response, Long organizationId) {
        if (!scan.getOrganizationId().equals(organizationId)
                || !scan.getTargetType().equals(response.getTargetType())) {
            throw new IllegalArgumentException("Discovery response identity does not match requestId="
                    + response.getRequestId());
        }
        if (scan.getStatus() == DiscoveryScanStatus.FAILED) {
            throw new IllegalStateException("Discovery scan already failed for requestId=" + response.getRequestId());
        }
    }

    private void validateBatchBounds(CertDiscoveryResponse response) {
        if (response.getTotalBatches() <= 0) {
            throw new IllegalArgumentException("Discovery totalBatches must be positive");
        }
        if (response.getBatchIndex() < 0 || response.getBatchIndex() >= response.getTotalBatches()) {
            throw new IllegalArgumentException("Discovery batchIndex is outside totalBatches");
        }
    }

    private OffsetDateTime parseTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return OffsetDateTime.now(ZoneOffset.UTC);
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Discovery completedAt must be ISO-8601", exception);
        }
    }
}
