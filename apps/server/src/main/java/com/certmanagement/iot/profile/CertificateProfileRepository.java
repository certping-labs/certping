// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.List;

public interface CertificateProfileRepository
        extends JpaRepository<CertificateProfile, Long>, JpaSpecificationExecutor<CertificateProfile> {

    Optional<CertificateProfile> findByProfileXrefAndOrganizationId(
            String profileXref, Long organizationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT profile FROM CertificateProfile profile "
            + "WHERE profile.profileXref = :profileXref "
            + "AND profile.organizationId = :organizationId")
    Optional<CertificateProfile> lockByProfileXrefAndOrganizationId(
            @Param("profileXref") String profileXref,
            @Param("organizationId") Long organizationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT profile FROM CertificateProfile profile "
            + "WHERE profile.latestOperationXref = :operationXref "
            + "AND profile.organizationId = :organizationId "
            + "AND profile.deviceSourceId = :deviceSourceId")
    Optional<CertificateProfile> lockByLatestOperation(
            @Param("operationXref") String operationXref,
            @Param("organizationId") Long organizationId,
            @Param("deviceSourceId") Long deviceSourceId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CertificateProfile> findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
            Long deviceSourceId, String providerProfileType, String providerProfileId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CertificateProfile> findByDeviceSourceIdAndProviderCorrelationMarker(
            Long deviceSourceId, String providerCorrelationMarker);

    /**
     * Resolves a provider-native profile-id hint within one source. A list, not an Optional:
     * the caller links only when exactly one profile matches and marks two-or-more AMBIGUOUS.
     */
    java.util.List<CertificateProfile> findAllByDeviceSourceIdAndProviderProfileId(
            Long deviceSourceId, String providerProfileId);

    List<CertificateProfile> findAllByDeviceSourceIdAndProviderProfileIdIn(
            Long deviceSourceId, List<String> providerProfileIds);

    /**
     * Marks native profiles absent from one fully received provider inventory.
     *
     * <p>Profiles without a provider id are excluded because an asynchronous create by the server may not
     * have reached Intune yet. Archived rows remain archived and are not resurrected by sync.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE CertificateProfile profile
               SET profile.providerSyncStatus = com.certmanagement.iot.profile.ProviderSyncStatus.NOT_FOUND,
                   profile.providerSyncError = :reason,
                   profile.updatedAt = :reconciledAt
             WHERE profile.deviceSourceId = :deviceSourceId
               AND profile.lifecycleStatus <> com.certmanagement.iot.profile.ProfileLifecycleStatus.ARCHIVED
               AND profile.providerProfileId IS NOT NULL
               AND (profile.lastProviderSyncXref IS NULL
                    OR profile.lastProviderSyncXref <> :syncXref)
            """)
    int markMissingFromCompletedSync(
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("syncXref") String syncXref,
            @Param("reason") String reason,
            @Param("reconciledAt") java.time.OffsetDateTime reconciledAt);
}
