// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.UserDomainCertEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserDomainCertRepository extends JpaRepository<UserDomainCertEntity, Long> {

    Optional<UserDomainCertEntity> findByOrganizationIdAndDomain(Long organizationId, String domain);

    boolean existsByOrganizationIdAndDomain(Long organizationId, String domain);

    long countByOrganizationIdAndIsDeletedFalse(Long organizationId);

    @Modifying
    @Query("UPDATE UserDomainCertEntity u SET u.isDeleted = true, u.deletedAt = CURRENT_TIMESTAMP " +
           "WHERE u.organizationId = :organizationId AND u.isDeleted = false")
    int softDeleteByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Soft-delete a single managed-domain row (org-scoped). Called by the cascade-
     * delete-domain endpoint after every dependent table has been soft-deleted.
     */
    @Modifying
    @Query("UPDATE UserDomainCertEntity u SET u.isDeleted = true, u.deletedAt = CURRENT_TIMESTAMP " +
           "WHERE u.id = :id AND u.organizationId = :organizationId AND u.isDeleted = false")
    int softDeleteByIdAndOrganizationId(@Param("id") Long id, @Param("organizationId") Long organizationId);

    @Modifying
    @Query("UPDATE UserDomainCertEntity u SET u.isDeleted = true, u.deletedAt = CURRENT_TIMESTAMP " +
           "WHERE u.userId = :userId AND u.isDeleted = false")
    int softDeleteByUserId(@Param("userId") Integer userId);

    @Modifying
    @NativeQuery("DELETE FROM user_domain_certificate WHERE organization_id = :organizationId " +
                   "AND is_deleted = true AND deleted_at < :cutoff")
    int hardDeleteByOrganizationIdAndDeletedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") java.time.OffsetDateTime cutoff);

    @Modifying
    @NativeQuery("DELETE FROM user_domain_certificate WHERE is_deleted = true AND deleted_at < :cutoff")
    int hardDeleteAllWithDeletedAtBefore(@Param("cutoff") java.time.OffsetDateTime cutoff);
}
