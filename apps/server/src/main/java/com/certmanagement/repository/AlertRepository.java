// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.AlertEntity;
import com.certmanagement.enums.AlertTypeEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;

@Repository
public interface AlertRepository extends JpaRepository<AlertEntity, Long> {

    /** All alerts owned by a user (no organization), most recently created first. */
    List<AlertEntity> findByUserIdOrderByCreatedAtDesc(Integer userId);

    /** Alerts owned by a user (no organization) filtered by type, most recently created first. */
    List<AlertEntity> findByUserIdAndAlertTypeOrderByCreatedAtDesc(Integer userId, AlertTypeEnum alertType);

    /** All alerts for an organization, most recently created first. */
    List<AlertEntity> findByOrganizationIdOrderByCreatedAtDesc(Long organizationId);

    /** Alerts for an organization filtered by type, most recently created first. */
    List<AlertEntity> findByOrganizationIdAndAlertTypeOrderByCreatedAtDesc(Long organizationId, AlertTypeEnum alertType);

    @Modifying
    @Query("UPDATE AlertEntity a SET a.isDeleted = true WHERE a.organizationId = :orgId AND a.isDeleted = false")
    int softDeleteByOrganizationId(@Param("orgId") Long orgId);

    @Modifying
    @Query("UPDATE AlertEntity a SET a.isDeleted = true WHERE a.userId = :userId AND a.isDeleted = false")
    int softDeleteByUserId(@Param("userId") Integer userId);

    /** Soft-deleted alerts only. {@code alert} has no {@code deleted_at}, so age is measured from creation. */
    @Modifying
    @NativeQuery("DELETE FROM alert WHERE organization_id = :organizationId " +
                   "AND is_deleted = true AND created_at < :cutoff")
    int hardDeleteByOrganizationIdAndCreatedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") OffsetDateTime cutoff);

    @Modifying
    @NativeQuery("DELETE FROM alert WHERE created_at < :cutoff")
    int hardDeleteAllWithCreatedAtBefore(@Param("cutoff") OffsetDateTime cutoff);
}
