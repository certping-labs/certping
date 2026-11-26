// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DiscoveredCertObservationEntity;
import com.certmanagement.entity.DiscoveryObservationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Set;

public interface DiscoveredCertObservationRepository
        extends JpaRepository<DiscoveredCertObservationEntity, Long> {

    List<DiscoveredCertObservationEntity> findAllByDiscoveredCertIdInAndScopeKey(
            Collection<Long> discoveredCertIds, String scopeKey);

    List<DiscoveredCertObservationEntity> findAllByScopeKey(String scopeKey);

    List<DiscoveredCertObservationEntity>
            findAllByOrganizationIdAndTargetTypeAndCredentialXrefAndScopeKeyNot(
                    Long organizationId, String targetType, String credentialXref, String scopeKey);

    @Query("""
            SELECT DISTINCT observation.discoveredCertId
            FROM DiscoveredCertObservationEntity observation
            WHERE observation.discoveredCertId IN :certificateIds
              AND observation.status = :status
            """)
    Set<Long> findCertificateIdsWithStatus(
            @Param("certificateIds") Collection<Long> certificateIds,
            @Param("status") DiscoveryObservationStatus status);

    /**
     * Returns the (discoveredCertId, credentialXref) pairs for the given certs, most-recently-seen
     * first, so callers can map each discovered cert to the credential that last observed it.
     */
    @Query("""
            SELECT observation.discoveredCertId AS discoveredCertId,
                   observation.credentialXref AS credentialXref
            FROM DiscoveredCertObservationEntity observation
            WHERE observation.discoveredCertId IN :certificateIds
            ORDER BY observation.lastSeenAt DESC
            """)
    List<DiscoveredCertCredentialView> findCredentialXrefsByDiscoveredCertIdIn(
            @Param("certificateIds") Collection<Long> certificateIds);

    /** Projection of a discovered cert id to the credential xref that observed it. */
    interface DiscoveredCertCredentialView {
        Long getDiscoveredCertId();

        String getCredentialXref();
    }

}
