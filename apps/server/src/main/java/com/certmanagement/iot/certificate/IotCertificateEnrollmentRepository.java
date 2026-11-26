// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.alert.OrganizationCount;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface IotCertificateEnrollmentRepository extends JpaRepository<IotCertificateEnrollment, Long> {

    interface StatusCount {
        Long getOrganizationId();

        String getStatus();

        long getTotal();
    }

    /**
     * Every enrollment outcome in the window, so a caller can judge a failure rate rather than a raw
     * failure count. Filtered on requestedAt to match idx_iot_cert_enrollment_org_status.
     */
    @Query("""
            SELECT enrollment.organizationId AS organizationId,
                   enrollment.status AS status,
                   COUNT(enrollment) AS total
              FROM IotCertificateEnrollment enrollment
             WHERE enrollment.requestedAt >= :from
             GROUP BY enrollment.organizationId, enrollment.status
            """)
    List<StatusCount> countByOrganizationAndStatus(@Param("from") OffsetDateTime from);

    /**
     * Enrollments whose device could not be told apart from another. The certificate is issued but
     * bound to nothing, so it needs a human to say which device it belongs to.
     */
    @Query("""
            SELECT enrollment.organizationId AS organizationId, COUNT(enrollment) AS total
              FROM IotCertificateEnrollment enrollment
             WHERE enrollment.deviceMatchStatus = 'AMBIGUOUS'
               AND enrollment.requestedAt >= :from
             GROUP BY enrollment.organizationId
            """)
    List<OrganizationCount> countAmbiguousDeviceMatches(@Param("from") OffsetDateTime from);

    /**
     * Serializes only deliveries for one source-scoped transaction. A hash collision can delay an
     * unrelated transaction but cannot merge data or weaken a database constraint. PostgreSQL
     * releases this advisory lock automatically when the surrounding transaction finishes.
     */
    @NativeQuery("""
            SELECT pg_advisory_xact_lock(
                hashtextextended(CAST(:deviceSourceId AS text) || ':' || :transactionId, 0))
            """)
    void lockTransaction(
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("transactionId") String transactionId);

    /**
     * Enrollment identity is source-scoped: the same Intune transaction id in two different
     * sources is two enrollments, and no profile is required to dedupe.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<IotCertificateEnrollment> findByOrganizationIdAndDeviceSourceIdAndTransactionId(
            Long organizationId, Long deviceSourceId, String transactionId);

    /**
     * Re-link candidates after a device sync: enrollments whose Microsoft-validated identifier
     * had no matching device at issuance, restricted to ones whose device exists NOW. The EXISTS
     * predicate keeps permanently-unresolvable enrollments (device deleted in the provider) from
     * occupying the bounded window forever and starving the tail. It spans both identifier
     * namespaces the server stores, because the agent cannot tell which one a validated CSR
     * subject carries.
     *
     * <p>Pending rows are taken oldest first so none waits forever; ambiguous rows are taken
     * newest first, because the one most likely to resolve is the one whose duplicate device was
     * just orphaned. A source holding a permanent backlog of genuinely ambiguous identifiers would
     * otherwise fill the window with rows that can never change and shut out the row that can.
     *
     * <p>{@code AMBIGUOUS} rows re-enter the window, but only after a sync that actually retired
     * its stale devices. Two rows answering to one identifier is usually not a permanent fact: a
     * device removed from the source and enrolled again has two rows until the stale one is
     * orphaned, and a certificate issued in that gap was refused a link for a reason that no
     * longer holds. {@code DEVICE_NOT_SYNCED} rows sort first so a source with genuinely ambiguous
     * identifiers can never starve the ones simply waiting for their device to arrive.
     *
     * <p>Native rather than JPQL on purpose: Hibernate renders {@code FUNCTION('jsonb_extract_path_text')}
     * as a different function than {@code ->>}, and PostgreSQL matches expression indexes by
     * expression-tree equality — so the JPQL form silently bypasses
     * {@code idx_iot_device_source_entra_device_id} and degrades to a nested-loop scan inside the
     * sync transaction. Written as {@code ->>} it uses the index.
     */
    @NativeQuery("""
            SELECT enrollment.* FROM iot_certificate_enrollment enrollment
             WHERE enrollment.device_source_id = :deviceSourceId
               AND (enrollment.device_match_status = 'DEVICE_NOT_SYNCED'
                    OR (CAST(:staleDevicesRetired AS boolean)
                        AND enrollment.device_match_status = 'AMBIGUOUS'))
               AND EXISTS (
                     SELECT 1 FROM iot_device device
                      WHERE device.device_source_id = enrollment.device_source_id
                        AND device.is_deleted = false
                        AND device.status = 'REGISTERED'
                        AND (
                            (enrollment.source_identifier_type = 'MANAGED_DEVICE_ID'
                             AND device.source_device_id = enrollment.asserted_source_device_id)
                            OR
                            (enrollment.source_identifier_type = 'UNKNOWN'
                             AND (device.source_device_id = enrollment.asserted_source_device_id
                                  OR device.source_identifiers_json ->> 'entraDeviceId'
                                     = enrollment.asserted_source_device_id))))
             ORDER BY CASE WHEN enrollment.device_match_status = 'DEVICE_NOT_SYNCED'
                           THEN 0 ELSE 1 END,
                      CASE WHEN enrollment.device_match_status = 'DEVICE_NOT_SYNCED'
                           THEN enrollment.id END ASC,
                      enrollment.id DESC
             LIMIT 500
            """)
    List<IotCertificateEnrollment> findRelinkableByDeviceSourceId(
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("staleDevicesRetired") boolean staleDevicesRetired);

    /**
     * Renewals that inherited no device because the certificate they renewed had none yet.
     *
     * <p>A renewal copies its device from the exact prior certificate. If that certificate was
     * still unlinked at the time — issued before its device had synced, or while a duplicate row
     * made the identifier ambiguous — the renewal inherits null, and it carries no identifier of
     * its own to be re-resolved from. Nothing else revisits those rows, so the live credential of
     * a device that renews on a short cycle can end up permanently unattributable while its
     * expired predecessor is the one still shown as current.
     *
     * <p>{@code RENEWAL_SOURCE_NOT_FOUND} is included for the same reason. That is written when the
     * predecessor was not in the inventory at all — the two certificates arrive as independent
     * messages, so the renewal can be ingested first — and it was equally terminal. The EXISTS
     * clause proves the predecessor is there now, whichever way the row was stamped.
     *
     * <p>Selected once the prior certificate has since gained a device. A chain resolves one link
     * per sync, which is enough: chains only grow while a source stays unsynced.
     */
    @NativeQuery("""
            SELECT enrollment.* FROM iot_certificate_enrollment enrollment
             WHERE enrollment.device_source_id = :deviceSourceId
               AND enrollment.enrollment_type = 'RENEWAL'
               AND enrollment.device_id IS NULL
               AND enrollment.device_match_status IN (
                     'INHERITED_FROM_RENEWAL', 'RENEWAL_SOURCE_NOT_FOUND')
               AND EXISTS (
                     SELECT 1 FROM iot_device_certificate prior
                      WHERE prior.organization_id = enrollment.organization_id
                        AND prior.device_source_id = enrollment.device_source_id
                        AND prior.issuer_dn = enrollment.prior_certificate_issuer_dn
                        AND prior.serial_number = enrollment.prior_certificate_serial_number
                        AND prior.device_id IS NOT NULL)
             ORDER BY enrollment.id ASC
             LIMIT 500
            """)
    List<IotCertificateEnrollment> findRenewalsAwaitingTheirPriorDevice(
            @Param("deviceSourceId") Long deviceSourceId);

    /**
     * Ids of the links worth repairing on the device page being orphaned, most recent first per
     * device.
     *
     * <p>Ranked per device rather than capped across the page. Every renewal mints its own
     * enrollment row, so one device that has been renewing for years holds the highest ids in the
     * page; a single global cap would let it consume the whole budget and leave every other
     * device's live certificate unrepaired. Repair is one-shot — an orphaned row is never selected
     * again — so anything skipped here is skipped permanently, which makes fairness the property
     * that matters.
     *
     * <p>Every usable link is selected, and only the dead tail is capped. Repair is one-shot — an
     * orphaned row is never selected again — so skipping a usable link strands a live credential
     * permanently, and there is no number of live certificates per device that can be assumed
     * safe. Dead links are different: they point at the row their certificate was actually issued
     * against, so losing the oldest of them costs nothing, and they are the half a long-renewing
     * device could otherwise flood the page with.
     *
     * <p>The dead tail is repaired at all, rather than dropped, because a recently expired
     * certificate still seeds renewals: {@code resolveRenewal} copies its device from the exact
     * prior certificate without consulting {@code iot_device}, so a predecessor left on the
     * orphaned row hands that row to the next renewal. Newest-first keeps the predecessors most
     * likely to be renewed against.
     *
     * <p>Usability is computed once in the innermost query so the partition and the filter cannot
     * disagree about what it means.
     */
    @NativeQuery("""
            SELECT ranked.id FROM (
                SELECT link.id,
                       link.usable,
                       ROW_NUMBER() OVER (
                           PARTITION BY link.device_id, link.usable
                           ORDER BY link.id DESC) AS device_rank
                  FROM (
                    SELECT enrollment.id,
                           enrollment.device_id,
                           (certificate.id IS NOT NULL
                            AND certificate.status <> 'REVOKED'
                            AND certificate.valid_to > :now) AS usable
                      FROM iot_certificate_enrollment enrollment
                      LEFT JOIN iot_device_certificate certificate
                             ON certificate.enrollment_id = enrollment.id
                     WHERE enrollment.device_id IN (:deviceIds)
                       AND enrollment.device_match_status IN (
                             'MATCHED', 'INHERITED_FROM_RENEWAL')
                  ) link
            ) ranked
             WHERE ranked.usable OR ranked.device_rank <= :perDevice
            """)
    List<Long> findRepairableLinkIds(
            @Param("deviceIds") List<Long> deviceIds,
            @Param("now") OffsetDateTime now,
            @Param("perDevice") int perDevice);

    /**
     * Locks those links in id order.
     *
     * <p>Separate from the ranking query because a locking clause cannot be applied to a query
     * containing a window function. Ordered so every writer takes enrollment locks in one
     * sequence, and taken after the device locks the caller already holds — see
     * {@code IotCertificateIngestionService}, which takes the same device-before-enrollment order.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT enrollment FROM IotCertificateEnrollment enrollment
             WHERE enrollment.id IN :ids
             ORDER BY enrollment.id
            """)
    List<IotCertificateEnrollment> lockLinksForRepair(@Param("ids") List<Long> ids);

}
