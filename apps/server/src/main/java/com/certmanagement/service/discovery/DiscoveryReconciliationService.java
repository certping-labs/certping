// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.entity.DiscoveredCertObservationEntity;
import com.certmanagement.entity.DiscoveryInventoryStatus;
import com.certmanagement.entity.DiscoveryObservationStatus;
import com.certmanagement.entity.DiscoveryScanEntity;
import com.certmanagement.repository.DiscoveredCertObservationRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import com.certmanagement.messaging.model.DiscoveryFailedScope;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class DiscoveryReconciliationService {

    private final DiscoveredCertObservationRepository observationRepository;
    private final DiscoveredCertRepository discoveredCertRepository;

    public void reconcile(DiscoveryScanEntity scan, OffsetDateTime now) {
        reconcile(scan, now, List.of());
    }

    /**
     * Reconciles a finished scan. A certificate the scan did not see is marked MISSING, unless it
     * lies in one of {@code failedScopes}: the agent could not read that account, region,
     * vault or namespace, so its certificates are left exactly as they were.
     */
    public void reconcile(DiscoveryScanEntity scan, OffsetDateTime now, List<DiscoveryFailedScope> failedScopes) {
        Set<Long> affectedCertificateIds = reconcileCurrentScope(scan, now,
                failedScopes == null ? List.of() : failedScopes);
        affectedCertificateIds.addAll(retirePreviousCredentialScopes(scan));
        refreshInventoryStatus(affectedCertificateIds, now);
    }

    private Set<Long> reconcileCurrentScope(DiscoveryScanEntity scan, OffsetDateTime now,
                                            List<DiscoveryFailedScope> failedScopes) {
        Set<Long> affected = new HashSet<>();
        List<DiscoveredCertObservationEntity> observations = observationRepository.findAllByScopeKey(scan.getScopeKey());
        Map<Long, String> resourceIds = failedScopes.isEmpty() ? Map.of() : resourceIdsOfUnseen(scan, observations);
        for (DiscoveredCertObservationEntity observation : observations) {
            if (observation.getStatus() == DiscoveryObservationStatus.PRESENT
                    && !scan.getRequestId().equals(observation.getLastSeenRequestId())) {
                if (!failedScopes.isEmpty()
                        && FailedScopes.coversAny(failedScopes, resourceIds.get(observation.getDiscoveredCertId()))) {
                    continue;
                }
                observation.setStatus(DiscoveryObservationStatus.MISSING);
                observation.setMissingSince(now);
                affected.add(observation.getDiscoveredCertId());
            }
        }
        observationRepository.saveAll(observations);
        return affected;
    }

    /** The resourceId of each certificate the scan did not see; a certificate not found maps to null (covered). */
    private Map<Long, String> resourceIdsOfUnseen(DiscoveryScanEntity scan,
                                                  List<DiscoveredCertObservationEntity> observations) {
        Set<Long> unseen = new HashSet<>();
        for (DiscoveredCertObservationEntity observation : observations) {
            if (observation.getStatus() == DiscoveryObservationStatus.PRESENT
                    && !scan.getRequestId().equals(observation.getLastSeenRequestId())) {
                unseen.add(observation.getDiscoveredCertId());
            }
        }
        if (unseen.isEmpty()) {
            return Map.of();
        }
        Map<Long, String> resourceIds = new HashMap<>();
        for (DiscoveredCertEntity certificate : discoveredCertRepository.findAllById(unseen)) {
            resourceIds.put(certificate.getId(), certificate.getResourceId());
        }
        return resourceIds;
    }

    private Set<Long> retirePreviousCredentialScopes(DiscoveryScanEntity scan) {
        Set<Long> affected = new HashSet<>();
        List<DiscoveredCertObservationEntity> observations = observationRepository
                .findAllByOrganizationIdAndTargetTypeAndCredentialXrefAndScopeKeyNot(
                        scan.getOrganizationId(), scan.getTargetType(), scan.getCredentialXref(), scan.getScopeKey());
        for (DiscoveredCertObservationEntity observation : observations) {
            if (observation.getStatus() != DiscoveryObservationStatus.OUT_OF_SCOPE) {
                observation.setStatus(DiscoveryObservationStatus.OUT_OF_SCOPE);
                observation.setMissingSince(null);
                affected.add(observation.getDiscoveredCertId());
            }
        }
        observationRepository.saveAll(observations);
        return affected;
    }

    private void refreshInventoryStatus(Set<Long> certificateIds, OffsetDateTime now) {
        if (certificateIds.isEmpty()) {
            return;
        }
        Set<Long> presentIds = observationRepository.findCertificateIdsWithStatus(
                certificateIds, DiscoveryObservationStatus.PRESENT);
        Set<Long> missingIds = observationRepository.findCertificateIdsWithStatus(
                certificateIds, DiscoveryObservationStatus.MISSING);
        Set<Long> outOfScopeIds = observationRepository.findCertificateIdsWithStatus(
                certificateIds, DiscoveryObservationStatus.OUT_OF_SCOPE);
        List<DiscoveredCertEntity> certificates = discoveredCertRepository.findAllById(certificateIds);
        for (DiscoveredCertEntity certificate : certificates) {
            if (presentIds.contains(certificate.getId())) {
                certificate.setInventoryStatus(DiscoveryInventoryStatus.PRESENT);
                certificate.setMissingSince(null);
            } else if (missingIds.contains(certificate.getId())) {
                certificate.setInventoryStatus(DiscoveryInventoryStatus.MISSING);
                if (certificate.getMissingSince() == null) {
                    certificate.setMissingSince(now);
                }
            } else if (outOfScopeIds.contains(certificate.getId())) {
                certificate.setInventoryStatus(DiscoveryInventoryStatus.UNKNOWN);
                certificate.setMissingSince(null);
            }
        }
        discoveredCertRepository.saveAll(certificates);
    }
}
