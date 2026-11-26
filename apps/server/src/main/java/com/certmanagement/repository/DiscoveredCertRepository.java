// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DiscoveredCertEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface DiscoveredCertRepository
        extends JpaRepository<DiscoveredCertEntity, Long>,
                JpaSpecificationExecutor<DiscoveredCertEntity> {

    Optional<DiscoveredCertEntity> findByOrganizationIdAndResourceId(Long organizationId, String resourceId);

    Optional<DiscoveredCertEntity> findByIdAndOrganizationId(Long id, Long organizationId);

    /** Batch fetch — used to avoid N+1 during discovery result persistence. */
    List<DiscoveredCertEntity> findAllByOrganizationIdAndResourceIdIn(Long organizationId, List<String> resourceIds);

    long countByOrganizationId(Long organizationId);

    /** One row per distinct raw key algorithm and key usage among the discovered certs PQC readiness covers. */
    interface PqcDiscoveredAlgorithmCount {
        String getKeyAlgorithm();
        String getKeyUsage();
        long getCount();
    }

    interface PqcDiscoveredRow {
        String getResourceId();
        String getDomain();
        String getSubjectDn();
        String getSignatureAlgorithm();
        String getKeyAlgorithm();
        String getKeyUsage();
    }

    /*
     * The discovered certs PQC readiness covers: still present, not one CertPing manages (those are counted from
     * the certificates table), and one row per serial when the same cert was found in several places.
     */
    String PQC_ELIGIBLE = """
            d.organizationId = :organizationId
              AND (d.managed IS NULL OR d.managed = false)
              AND d.inventoryStatus <> com.certmanagement.entity.DiscoveryInventoryStatus.MISSING
              AND (d.serialNumber IS NULL OR NOT EXISTS (
                  SELECT 1 FROM DiscoveredCertEntity o
                  WHERE o.organizationId = d.organizationId
                    AND o.serialNumber = d.serialNumber
                    AND (o.managed IS NULL OR o.managed = false)
                    AND o.inventoryStatus <> com.certmanagement.entity.DiscoveryInventoryStatus.MISSING
                    AND o.id < d.id))
            """;

    @Query("SELECT d.keyAlgorithm AS keyAlgorithm, d.keyUsage AS keyUsage, COUNT(d) AS count "
            + "FROM DiscoveredCertEntity d WHERE " + PQC_ELIGIBLE
            + " GROUP BY d.keyAlgorithm, d.keyUsage")
    List<PqcDiscoveredAlgorithmCount> countPqcAlgorithmsByOrganizationId(@Param("organizationId") Long organizationId);

    /** {@code keyAlgorithms} (nullable) restricts to these raw values, with an empty string standing for null. */
    @Query("SELECT d.resourceId AS resourceId, d.domain AS domain, d.subjectDn AS subjectDn, "
            + "d.signatureAlgorithm AS signatureAlgorithm, d.keyAlgorithm AS keyAlgorithm, d.keyUsage AS keyUsage "
            + "FROM DiscoveredCertEntity d WHERE " + PQC_ELIGIBLE
            + " AND (:keyAlgorithms IS NULL OR COALESCE(d.keyAlgorithm, '') IN :keyAlgorithms)")
    List<PqcDiscoveredRow> findPqcRowsByOrganizationId(
            @Param("organizationId") Long organizationId,
            @Param("keyAlgorithms") Collection<String> keyAlgorithms,
            Pageable pageable);

    @Query("SELECT COUNT(d) FROM DiscoveredCertEntity d WHERE " + PQC_ELIGIBLE
            + " AND (:keyAlgorithms IS NULL OR COALESCE(d.keyAlgorithm, '') IN :keyAlgorithms)")
    long countPqcRowsByOrganizationId(
            @Param("organizationId") Long organizationId,
            @Param("keyAlgorithms") Collection<String> keyAlgorithms);
}
