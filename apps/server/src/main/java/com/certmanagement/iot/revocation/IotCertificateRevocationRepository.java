// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.alert.OrganizationCount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.List;
import java.util.Collection;

public interface IotCertificateRevocationRepository
        extends JpaRepository<IotCertificateRevocation, Long> {

    /**
     * Revocations that never reached a terminal state. Keeping the status predicate lets this ride
     * the partial idx_iot_certificate_revocation_due index.
     */
    @Query("""
            SELECT operation.organizationId AS organizationId, COUNT(operation) AS total
              FROM IotCertificateRevocation operation
             WHERE operation.status IN :statuses
               AND operation.createdAt < :createdBefore
             GROUP BY operation.organizationId
            """)
    List<OrganizationCount> countUnfinished(
            @Param("statuses") Collection<IotCertificateRevocationStatus> statuses,
            @Param("createdBefore") OffsetDateTime createdBefore);

    Optional<IotCertificateRevocation> findByOrganizationIdAndIdempotencyKey(
            Long organizationId, String idempotencyKey);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<IotCertificateRevocation> findByOrganizationIdAndOperationXref(
            Long organizationId, String operationXref);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<IotCertificateRevocation> findAllByIdIn(Collection<Long> ids);

    Optional<IotCertificateRevocation> findFirstByCertificateIdAndStatusInOrderByIdDesc(
            Long certificateId, Iterable<IotCertificateRevocationStatus> statuses);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<IotCertificateRevocation> findByDeviceSourceIdAndRequestContextHash(
            Long deviceSourceId, String requestContextHash);

    List<IotCertificateRevocation> findAllByDeviceSourceIdAndIntuneTransactionIdOrderById(
            Long deviceSourceId, String intuneTransactionId);

    long countByDeviceSourceIdAndIntuneTransactionIdAndStatusIn(
            Long deviceSourceId, String intuneTransactionId,
            Iterable<IotCertificateRevocationStatus> statuses);

    @NativeQuery("""
            SELECT *
              FROM iot_certificate_revocation
             WHERE status IN ('PENDING','DISPATCHED')
               AND next_attempt_at <= :now
             ORDER BY next_attempt_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """)
    List<IotCertificateRevocation> claimDue(@Param("now") OffsetDateTime now,
                                             @Param("limit") int limit);
}
