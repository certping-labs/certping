// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CertificateEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateEventRepository extends JpaRepository<CertificateEventEntity, Long> {

    List<CertificateEventEntity> findByCertificateXrefOrderByOccurredAtDesc(String certificateXref);

    List<CertificateEventEntity> findByOrganizationIdOrderByOccurredAtDesc(Long organizationId);

    /** Physical purge; must run before the certificates it references, which it restricts. */
    @Modifying
    @NativeQuery("DELETE FROM certificate_events ce WHERE EXISTS (" +
                   "SELECT 1 FROM certificates c JOIN user_domain_certificate udc " +
                   "ON udc.id = c.user_domain_cert_id " +
                   "WHERE c.certificate_xref = ce.certificate_xref " +
                   "AND udc.organization_id = :organizationId " +
                   "AND c.deleted_at IS NOT NULL AND c.deleted_at < :cutoff)")
    int hardDeleteByOrganizationIdAndCertificateDeletedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") OffsetDateTime cutoff);

    /**
     * Dedup check — mirrors the DB partial unique index:
     * {@code idx_cert_events_idempotency (request_id, event_type) WHERE request_id IS NOT NULL}.
     *
     * <p>Called before every event insert when {@code requestId} is non-null so that
     * At-least-once re-delivery does not produce duplicate audit rows.
     * The DB constraint is the ultimate guard; this pre-check produces a clean INFO log
     * instead of a constraint-violation ERROR.
     */
    boolean existsByRequestIdAndEventType(String requestId, String eventType);

    /**
     * The member who made the request {@code requestId} names: the user of its earliest event written by
     * the server itself ({@code source}) with a user, if any. An agent response carries the request id of the
     * command it answers, so its audit row can say whose request it was ({@code requestedBy}). Bounded by the
     * request id index; one row read.
     */
    @NativeQuery("SELECT user_id FROM certificate_events WHERE request_id = :requestId AND source = :source "
            + "AND user_id IS NOT NULL ORDER BY occurred_at LIMIT 1")
    Optional<Integer> findFirstRequesterUserId(@Param("requestId") String requestId, @Param("source") String source);

    /**
     * Soft-delete every existing event for a certificate. Called by the cert delete
     * flow so the prior audit trail stops appearing in {@code @Where(is_deleted=false)}
     * queries while remaining in the table until the nightly hard-delete purge runs.
     *
     * <p>The CERT_DELETED event row inserted by {@code CertPersistenceService} after
     * this call defaults to {@code is_deleted=false}, so the soft-delete marker itself
     * stays visible.
     */
    @Modifying
    @NativeQuery("UPDATE certificate_events SET is_deleted = true "
            + "WHERE certificate_xref = :xref AND is_deleted = false")
    int softDeleteByCertificateXref(@Param("xref") String certificateXref);

    /**
     * Bulk soft-delete every still-visible event for an organization. Called from the
     * organization-delete cascade path, where individual certs are bulk-soft-deleted via
     * {@code CertificateRepository.softDeleteAllByOrganizationId} (not via
     * {@code CertPersistenceService.softDeleteAndInsertEvent}), so this helper is the
     * only place that flips events for org-wide delete.
     */
    @Modifying
    @NativeQuery("UPDATE certificate_events SET is_deleted = true "
            + "WHERE organization_id = :orgId AND is_deleted = false")
    int softDeleteByOrganizationId(@Param("orgId") Long organizationId);

    /** The source of each renewal that produced one of {@code renewedXrefs}: [renewedXref, source]. */
    @NativeQuery("SELECT details ->> 'renewedCertificateXref', source FROM certificate_events "
            + "WHERE organization_id = :orgId AND event_type = 'RENEWAL_REQUESTED' AND is_deleted = false "
            + "AND details ->> 'renewedCertificateXref' IN (:renewedXrefs)")
    List<Object[]> findRenewalSources(@Param("orgId") Long organizationId,
                                      @Param("renewedXrefs") Collection<String> renewedXrefs);
}
