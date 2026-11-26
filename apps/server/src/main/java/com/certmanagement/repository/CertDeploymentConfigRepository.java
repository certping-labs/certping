// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CertDeploymentConfigEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface CertDeploymentConfigRepository extends JpaRepository<CertDeploymentConfigEntity, Long> {

    Optional<CertDeploymentConfigEntity> findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
            Long organizationId, Long userDomainCertId, Long deploymentCredentialId);

    @Query("""
            SELECT c
            FROM CertDeploymentConfigEntity c
            WHERE c.organizationId = :organizationId
              AND c.userDomainCertId = :userDomainCertId
              AND c.deploymentCredentialXref = :deploymentCredentialXref
              AND c.isDeleted = false
            """)
    Optional<CertDeploymentConfigEntity> findActiveByCertAndCredentialXref(
            @Param("organizationId") Long organizationId,
            @Param("userDomainCertId") Long userDomainCertId,
            @Param("deploymentCredentialXref") String deploymentCredentialXref);

    /**
     * Soft-deletes every per-cert deployment config row that pins this credential xref.
     * Called when the underlying credential is soft-deleted so the next renewal does
     * not try to publish a deploy command for a soft-deleted credential.
     */
    @Transactional
    @Modifying
    @Query("""
            UPDATE CertDeploymentConfigEntity c
               SET c.isDeleted = true,
                   c.updatedAt = CURRENT_TIMESTAMP
             WHERE c.deploymentCredentialXref = :xref
               AND c.isDeleted = false
            """)
    int softDeleteByCredentialXref(@Param("xref") String credentialXref);

    /**
     * Bulk soft-delete every per-cert deployment config for an organization. Called
     * from the organization-delete cascade so this side of the deployment plumbing
     * is soft-deleted alongside the certs and credentials.
     */
    @Transactional
    @Modifying
    @Query("""
            UPDATE CertDeploymentConfigEntity c
               SET c.isDeleted = true,
                   c.updatedAt = CURRENT_TIMESTAMP
             WHERE c.organizationId = :orgId
               AND c.isDeleted = false
            """)
    int softDeleteByOrganizationId(@Param("orgId") Long organizationId);

    /**
     * Soft-delete every per-cert deployment config tied to a domain (UDC). Called from
     * the cascade-delete-domain flow, which removes the entire domain (UDC) along with
     * its credential / deployment configs that span all cert iterations on that domain.
     */
    @Transactional
    @Modifying
    @Query("""
            UPDATE CertDeploymentConfigEntity c
               SET c.isDeleted = true,
                   c.updatedAt = CURRENT_TIMESTAMP
             WHERE c.userDomainCertId = :udcId
               AND c.isDeleted = false
            """)
    int softDeleteByUserDomainCertId(@Param("udcId") Long userDomainCertId);
}
