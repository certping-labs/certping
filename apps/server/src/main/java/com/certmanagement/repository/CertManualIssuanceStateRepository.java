// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CertManualIssuanceStateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CertManualIssuanceStateRepository
        extends JpaRepository<CertManualIssuanceStateEntity, Long> {

    @Query("SELECT s FROM CertManualIssuanceStateEntity s WHERE s.certXref = :certXref AND s.isDeleted = false")
    Optional<CertManualIssuanceStateEntity> findByCertXref(@Param("certXref") String certXref);

    @Transactional
    @Modifying
    @Query("UPDATE CertManualIssuanceStateEntity s SET s.isDeleted = true, s.deletedAt = CURRENT_TIMESTAMP WHERE s.certXref = :certXref AND s.isDeleted = false")
    void deleteByCertXref(@Param("certXref") String certXref);

    @Transactional
    @Modifying
    @Query("UPDATE CertManualIssuanceStateEntity s SET s.isDeleted = true, s.deletedAt = CURRENT_TIMESTAMP " +
           "WHERE s.organizationId = :organizationId AND s.isDeleted = false")
    int softDeleteByOrganizationId(@Param("organizationId") Long organizationId);

    @Modifying
    @NativeQuery("DELETE FROM cert_manual_issuance_state WHERE organization_id = :organizationId " +
                   "AND is_deleted = true AND deleted_at < :cutoff")
    int hardDeleteByOrganizationIdAndDeletedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") java.time.OffsetDateTime cutoff);

    @Modifying
    @NativeQuery("DELETE FROM cert_manual_issuance_state WHERE is_deleted = true AND deleted_at < :cutoff")
    int hardDeleteAllWithDeletedAtBefore(@Param("cutoff") java.time.OffsetDateTime cutoff);
}
