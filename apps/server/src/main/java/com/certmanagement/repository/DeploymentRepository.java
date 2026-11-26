// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DeploymentEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Optional;

@Repository
public interface DeploymentRepository extends JpaRepository<DeploymentEntity, Long> {

    Optional<DeploymentEntity> findByRequestId(String requestId);

    Optional<DeploymentEntity> findByRequestIdAndOrganizationId(String requestId, Long organizationId);

    /**
     * Whether a deployment was requested for this certificate in this flow: an automatic deploy that
     * already went out must not go out again when an issuance or renewal response is redelivered.
     * Served by idx_deployments_cert_created_at.
     */
    boolean existsByCertificateXrefAndFlowType(String certificateXref, String flowType);

    @Query("""
        SELECT d FROM DeploymentEntity d
        WHERE d.organizationId = :organizationId
          AND COALESCE(d.isDeleted, FALSE) = FALSE
          AND d.certificateXref = COALESCE(:certificateXref, d.certificateXref)
          AND d.status = COALESCE(:status, d.status)
          AND d.targetType = COALESCE(:targetType, d.targetType)
          AND d.flowType = COALESCE(:flowType, d.flowType)
          AND (:filterByUserDomainCert = FALSE OR d.userDomainCertId = :userDomainCertId)
          AND d.createdAt >= COALESCE(:fromTs, d.createdAt)
          AND d.createdAt <= COALESCE(:toTs, d.createdAt)
        """)
    Page<DeploymentEntity> search(
            @Param("organizationId") Long organizationId,
            @Param("certificateXref") String certificateXref,
            @Param("status") String status,
            @Param("targetType") String targetType,
            @Param("flowType") String flowType,
            @Param("filterByUserDomainCert") boolean filterByUserDomainCert,
            @Param("userDomainCertId") Long userDomainCertId,
            @Param("fromTs") OffsetDateTime fromTs,
            @Param("toTs") OffsetDateTime toTs,
            Pageable pageable
    );

    @Query("""
        SELECT
          COUNT(d),
          SUM(CASE WHEN d.status = 'SUCCESS' THEN 1 ELSE 0 END),
          SUM(CASE WHEN d.status = 'FAILED' THEN 1 ELSE 0 END),
          SUM(CASE WHEN d.status = 'PUBLISH_FAILED' THEN 1 ELSE 0 END),
          SUM(CASE WHEN d.status IN ('DEPLOYING', 'REQUESTED', 'PUBLISHED') THEN 1 ELSE 0 END)
        FROM DeploymentEntity d
        WHERE d.organizationId = :organizationId
          AND COALESCE(d.isDeleted, FALSE) = FALSE
          AND d.certificateXref = COALESCE(:certificateXref, d.certificateXref)
          AND d.status = COALESCE(:status, d.status)
          AND d.targetType = COALESCE(:targetType, d.targetType)
          AND d.flowType = COALESCE(:flowType, d.flowType)
          AND (:filterByUserDomainCert = FALSE OR d.userDomainCertId = :userDomainCertId)
          AND d.createdAt >= COALESCE(:fromTs, d.createdAt)
          AND d.createdAt <= COALESCE(:toTs, d.createdAt)
        """)
    Object[] summary(
            @Param("organizationId") Long organizationId,
            @Param("certificateXref") String certificateXref,
            @Param("status") String status,
            @Param("targetType") String targetType,
            @Param("flowType") String flowType,
            @Param("filterByUserDomainCert") boolean filterByUserDomainCert,
            @Param("userDomainCertId") Long userDomainCertId,
            @Param("fromTs") OffsetDateTime fromTs,
            @Param("toTs") OffsetDateTime toTs
    );

    /**
     * Per-UDC deployment counts. {@code excludeEmpty=true} hides domains that have zero
     * deployments requested (HAVING COUNT(d) > 0), so the caller only sees UDCs with at
     * least one deployment row. Defaults to {@code false} for back-compat — older clients
     * still get every UDC, zeros included.
     *
     * <p>The countQuery has to mirror the same exclude-empty branch via an EXISTS
     * sub-query, otherwise pagination totals diverge from the items returned.
     */
    @Query(value = """
        SELECT
            udc.id,
            udc.domain,
            COUNT(d),
            SUM(CASE WHEN d.status = 'SUCCESS' THEN 1 ELSE 0 END),
            SUM(CASE WHEN d.status IN ('FAILED', 'PUBLISH_FAILED') THEN 1 ELSE 0 END)
        FROM UserDomainCertEntity udc
        LEFT JOIN DeploymentEntity d
            ON d.userDomainCertId = udc.id
           AND d.organizationId = :organizationId
            AND COALESCE(d.isDeleted, FALSE) = FALSE
        WHERE udc.organizationId = :organizationId
          AND (:domain IS NULL OR LOWER(udc.domain) LIKE LOWER(CONCAT('%', cast(:domain as String), '%')))
          AND (:filterByUserDomainCert = FALSE OR udc.id = :userDomainCertId)
        GROUP BY udc.id, udc.domain
        HAVING (:excludeEmpty = FALSE OR COUNT(d) > 0)
        """,
        countQuery = """
        SELECT COUNT(udc)
        FROM UserDomainCertEntity udc
        WHERE udc.organizationId = :organizationId
          AND (:domain IS NULL OR LOWER(udc.domain) LIKE LOWER(CONCAT('%', cast(:domain as String), '%')))
          AND (:filterByUserDomainCert = FALSE OR udc.id = :userDomainCertId)
          AND (
              :excludeEmpty = FALSE
              OR EXISTS (
                  SELECT 1 FROM DeploymentEntity d
                  WHERE d.userDomainCertId = udc.id
                    AND d.organizationId = :organizationId
                    AND COALESCE(d.isDeleted, FALSE) = FALSE
              )
          )
        """)
    Page<Object[]> summarizeByUserDomainCert(
            @Param("organizationId") Long organizationId,
            @Param("domain") String domain,
            @Param("filterByUserDomainCert") boolean filterByUserDomainCert,
            @Param("userDomainCertId") Long userDomainCertId,
            @Param("excludeEmpty") boolean excludeEmpty,
            Pageable pageable);

    @Modifying
    @Query("""
        UPDATE DeploymentEntity d
           SET d.isDeleted = TRUE,
               d.updatedAt = CURRENT_TIMESTAMP
         WHERE d.organizationId = :organizationId
           AND d.certificateXref = :certificateXref
           AND COALESCE(d.isDeleted, FALSE) = FALSE
        """)
    int softDeleteByCertificateXrefAndOrganizationId(
            @Param("certificateXref") String certificateXref,
            @Param("organizationId") Long organizationId);

    @Modifying
    @Query("""
        UPDATE DeploymentEntity d
           SET d.isDeleted = TRUE,
               d.updatedAt = CURRENT_TIMESTAMP
         WHERE d.organizationId = :organizationId
           AND COALESCE(d.isDeleted, FALSE) = FALSE
        """)
    int softDeleteByOrganizationId(@Param("organizationId") Long organizationId);

    @Query("""
        SELECT d FROM DeploymentEntity d
        WHERE d.requestId = :requestId
          AND d.organizationId = :organizationId
          AND COALESCE(d.isDeleted, FALSE) = FALSE
        """)
    Optional<DeploymentEntity> findActiveByRequestIdAndOrganizationId(
            @Param("requestId") String requestId,
            @Param("organizationId") Long organizationId);
}
