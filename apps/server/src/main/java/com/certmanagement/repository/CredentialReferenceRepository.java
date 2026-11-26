// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CredentialReferenceEntity;
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
public interface CredentialReferenceRepository extends JpaRepository<CredentialReferenceEntity, Long> {

    Optional<CredentialReferenceEntity> findByCredentialXrefAndOrganizationId(String credentialXref, Long organizationId);

    Optional<CredentialReferenceEntity> findByCredentialXref(String credentialXref);

    List<CredentialReferenceEntity> findByCredentialXrefIn(java.util.Collection<String> credentialXrefs);

        List<CredentialReferenceEntity> findByOrganizationIdAndStatusOrderByUpdatedAtDesc(Long organizationId, String status);

        List<CredentialReferenceEntity> findByOrganizationIdAndTypeAndStatusOrderByUpdatedAtDesc(
            Long organizationId, String type, String status);

    boolean existsByCredentialXrefAndOrganizationId(String credentialXref, Long organizationId);

    List<CredentialReferenceEntity> findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
            String provider, String type, String status, Long afterId, Pageable pageable);

    @Query("""
        SELECT DISTINCT c.secretHandle
        FROM CredentialReferenceEntity c
        WHERE c.organizationId = :organizationId
                AND c.isDeleted = false
        """)
    List<String> findDistinctKvPathsByOrganizationId(@Param("organizationId") Long organizationId);

    // Case-normalised so `AWS_ACM` and `aws_acm` don't both appear.
    @Query("""
        SELECT DISTINCT UPPER(c.provider)
          FROM CredentialReferenceEntity c
         WHERE c.type = 'DEPLOYMENT'
           AND c.provider IS NOT NULL
           AND c.isDeleted = false
         ORDER BY UPPER(c.provider)
        """)
    List<String> findDistinctDeploymentProviders();

    /** Safety guard before deleting a DNS or CA credential reference. Deployment
     *  credentials are passed per-deploy and not persisted on the cert row, so
     *  this does NOT cover deployment credential usage. */
    @NativeQuery("SELECT COUNT(DISTINCT c.id) FROM certificates c " +
            "JOIN user_domain_certificate udc ON udc.id = c.user_domain_cert_id " +
            "LEFT JOIN domain_credential_config dcc ON dcc.user_domain_cert_id = udc.id " +
            "WHERE (c.ca_credential_handle IN " +
            "  (SELECT cr.secret_handle FROM credential_references cr WHERE cr.credential_xref = :credXref) " +
            "  OR EXISTS (SELECT 1 FROM jsonb_each_text(dcc.dns_config) kv WHERE kv.value = :credXref)) " +
            "AND c.status NOT IN ('DELETED', 'EXPIRED', 'FAILED') AND c.deleted_at IS NULL")
    long countActiveCertsReferencingCredential(@Param("credXref") String credentialXref);

    /** Records why a target refused the credential; updatedAt is left alone, nothing about the credential changed. */
    @Modifying
    @Query("UPDATE CredentialReferenceEntity c SET c.lastErrorMessage = :message " +
           "WHERE c.credentialXref = :credentialXref AND c.organizationId = :organizationId")
    int recordLastError(@Param("credentialXref") String credentialXref,
                        @Param("organizationId") Long organizationId,
                        @Param("message") String message);

    @Modifying
    @Query("UPDATE CredentialReferenceEntity c SET c.lastErrorMessage = NULL " +
           "WHERE c.credentialXref = :credentialXref AND c.organizationId = :organizationId " +
           "AND c.lastErrorMessage IS NOT NULL")
    int clearLastError(@Param("credentialXref") String credentialXref,
                       @Param("organizationId") Long organizationId);

    @Modifying
    @Query("UPDATE CredentialReferenceEntity c SET c.isDeleted = true, c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.organizationId = :organizationId AND c.isDeleted = false")
    int softDeleteByOrganizationId(@Param("organizationId") Long organizationId);

    @Modifying
    @NativeQuery("DELETE FROM credential_references WHERE organization_id = :organizationId " +
                   "AND is_deleted = true AND updated_at < :cutoff")
    int hardDeleteByOrganizationIdAndUpdatedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") java.time.OffsetDateTime cutoff);

    @Modifying
    @NativeQuery("DELETE FROM credential_references WHERE is_deleted = true AND updated_at < :cutoff")
    int hardDeleteAllWithUpdatedAtBefore(@Param("cutoff") java.time.OffsetDateTime cutoff);
}
