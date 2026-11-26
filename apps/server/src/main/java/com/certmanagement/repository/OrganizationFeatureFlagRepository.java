// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.OrganizationFeatureFlag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrganizationFeatureFlagRepository extends JpaRepository<OrganizationFeatureFlag, Long> {

    Optional<OrganizationFeatureFlag> findByOrganizationIdAndFeatureKey(Long organizationId, String featureKey);

    /** The two columns the flag decision reads from an organization's override. */
    interface OverrideView {
        Boolean getEnabled();
        Boolean getAdminLocked();
    }

    /** Scalar read for the resolver: one query answers both "is there an override" and "is it locked". */
    @Query("SELECT o.enabled AS enabled, o.adminLocked AS adminLocked FROM OrganizationFeatureFlag o "
            + "WHERE o.organizationId = :orgId AND o.featureKey = :featureKey")
    Optional<OverrideView> findOverrideViewByOrganizationIdAndFeatureKey(@Param("orgId") Long organizationId,
                                                                         @Param("featureKey") String featureKey);

    /** Bypasses the {@code @Where(is_deleted=false)} filter — used by upsert to detect and restore soft-deleted rows. */
    @NativeQuery("SELECT * FROM organization_feature_flags WHERE organization_id = :orgId AND feature_key = :featureKey")
    Optional<OrganizationFeatureFlag> findByOrganizationIdAndFeatureKeyIncludeDeleted(@Param("orgId") Long orgId,
                                                                                       @Param("featureKey") String featureKey);

    List<OrganizationFeatureFlag> findAllByOrganizationId(Long organizationId);

    /** One flag's overrides for a bounded batch of organizations (callers chunk the ids). */
    List<OrganizationFeatureFlag> findAllByFeatureKeyAndOrganizationIdIn(String featureKey,
                                                                        java.util.Collection<Long> organizationIds);

    /** Every override of a bounded batch of organizations (callers chunk the ids). */
    List<OrganizationFeatureFlag> findAllByOrganizationIdIn(java.util.Collection<Long> organizationIds);

    Page<OrganizationFeatureFlag> findAllByFeatureKey(String featureKey, Pageable pageable);

    @Modifying
    @Query("UPDATE OrganizationFeatureFlag o SET o.isDeleted = true, o.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE o.organizationId = :orgId AND o.featureKey = :featureKey")
    int softDeleteByOrganizationIdAndFeatureKey(@Param("orgId") Long orgId,
                                                @Param("featureKey") String featureKey);

    @Modifying
    @Query("UPDATE OrganizationFeatureFlag o SET o.isDeleted = true, o.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE o.organizationId = :orgId AND o.featureKey = :featureKey AND o.adminLocked = false")
    int softDeleteUnlockedByOrganizationIdAndFeatureKey(@Param("orgId") Long orgId,
                                                        @Param("featureKey") String featureKey);

    @Modifying
    @Query("UPDATE OrganizationFeatureFlag o SET o.isDeleted = true, o.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE o.organizationId = :orgId AND o.isDeleted = false")
    int softDeleteAllByOrganizationId(@Param("orgId") Long orgId);
}
