// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DiscoveryConfigEntity;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface DiscoveryConfigRepository extends JpaRepository<DiscoveryConfigEntity, Long> {

    List<DiscoveryConfigEntity> findAllByOrganizationIdAndIsDeletedFalseOrderByUpdatedAtDesc(Long organizationId);

    Optional<DiscoveryConfigEntity> findByIdAndOrganizationIdAndIsDeletedFalse(Long id, Long organizationId);

    Optional<DiscoveryConfigEntity> findByLastRequestIdAndIsDeletedFalse(String lastRequestId);

    Optional<DiscoveryConfigEntity> findByLastRequestIdAndOrganizationIdAndIsDeletedFalse(
            String lastRequestId, Long organizationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT config
            FROM DiscoveryConfigEntity config
            WHERE config.organizationId = :organizationId
              AND config.targetType = :targetType
              AND config.credentialXref = :credentialXref
              AND config.isDeleted = false
            ORDER BY config.updatedAt DESC, config.id DESC
            """)
    List<DiscoveryConfigEntity> findByOrganizationIdAndTargetTypeAndCredentialXrefForUpdate(
            @Param("organizationId") Long organizationId,
            @Param("targetType") String targetType,
            @Param("credentialXref") String credentialXref);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT config
            FROM DiscoveryConfigEntity config
            WHERE config.organizationId = :organizationId
              AND config.isDeleted = false
            ORDER BY config.updatedAt DESC, config.id DESC
            """)
    List<DiscoveryConfigEntity> findAllByOrganizationIdForUpdate(@Param("organizationId") Long organizationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT config
            FROM DiscoveryConfigEntity config
            WHERE config.id = :id
              AND config.organizationId = :organizationId
              AND config.isDeleted = false
            """)
    Optional<DiscoveryConfigEntity> findByIdAndOrganizationIdForUpdate(
            @Param("id") Long id,
            @Param("organizationId") Long organizationId);
}
