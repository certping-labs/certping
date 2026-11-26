// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.alert.OrganizationCount;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface IotDeviceCertificateRepository extends JpaRepository<IotDeviceCertificate, Long> {

    /**
     * Certificates whose renewal was nudged but never came back. NUDGING is not a terminal state, so
     * a row that stays there long past its nudge means the device never acted on the check-in and
     * the certificate is heading for expiry with nobody watching.
     */
    @Query("""
            SELECT certificate.organizationId AS organizationId, COUNT(certificate) AS total
              FROM IotDeviceCertificate certificate
             WHERE certificate.renewalState = 'NUDGING'
               AND certificate.lastNudgedAt IS NOT NULL
               AND certificate.lastNudgedAt < :nudgedBefore
             GROUP BY certificate.organizationId
            """)
    List<OrganizationCount> countStuckInNudging(@Param("nudgedBefore") OffsetDateTime nudgedBefore);

    /**
     * Live certificates that never linked to a device. Linking is what makes renewal and revocation
     * possible, so an unlinked certificate is real but unmanageable. Recent issuances are excluded
     * because the device sync that links them legitimately lags.
     */
    @Query("""
            SELECT certificate.organizationId AS organizationId, COUNT(certificate) AS total
              FROM IotDeviceCertificate certificate
             WHERE certificate.deviceId IS NULL
               AND certificate.status IN ('ISSUED', 'ISSUED_PENDING_NOTIFICATION')
               AND certificate.issuedAt < :issuedBefore
             GROUP BY certificate.organizationId
            """)
    List<OrganizationCount> countUnlinked(@Param("issuedBefore") OffsetDateTime issuedBefore);

    /** Latest valid certificate for each requested device/profile pair. */
    /**
     * Ordered by primary key because this query takes row locks, and PostgreSQL acquires them in
     * the order the rows are produced. The certificate rebind that runs while a sync orphans
     * devices writes its updates in primary-key order over the same rows, so ordering this by
     * anything else — {@code (deviceId, profileId)} reads more naturally — lets a nudge and a sync
     * take the same two certificates in opposite orders and deadlock. The caller groups by device
     * itself and the eligibility assessment does not depend on the order.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT certificate
              FROM IotDeviceCertificate certificate
             WHERE certificate.organizationId = :organizationId
               AND certificate.deviceId IN :deviceIds
               AND certificate.profileId IS NOT NULL
               AND certificate.status = 'ISSUED'
               AND certificate.certificateAuthority = false
               AND certificate.validTo > :now
               AND certificate.renewalState IN ('NONE', 'NUDGING')
               AND NOT EXISTS (
                    SELECT newer.id
                      FROM IotDeviceCertificate newer
                     WHERE newer.organizationId = certificate.organizationId
                       AND newer.deviceId = certificate.deviceId
                       AND newer.profileId = certificate.profileId
                       AND newer.certificateAuthority = false
                       AND newer.status = 'ISSUED'
                       AND newer.validTo > :now
                       AND newer.issuedAt > certificate.issuedAt)
             ORDER BY certificate.id
            """)
    List<IotDeviceCertificate> findCurrentForDeviceSync(
            @Param("organizationId") Long organizationId,
            @Param("deviceIds") List<Long> deviceIds,
            @Param("now") OffsetDateTime now);

    /**
     * Prior current certificates for the same device and profile. A newer SCEP issuance proves
     * renewal even when CertPing never requested a device sync.
     */
    @Query("""
            SELECT c FROM IotDeviceCertificate c
             WHERE c.organizationId = :organizationId
               AND c.deviceId = :deviceId
               AND c.profileId = :profileId
               AND c.id <> :excludeCertificateId
               AND c.issuedAt < :issuedBefore
               AND c.status = 'ISSUED'
               AND c.certificateAuthority = false
               AND c.renewalState IN ('NONE','NUDGING')
            """)
    List<IotDeviceCertificate> findSupersededMonitoredCertificates(
            @Param("organizationId") Long organizationId,
            @Param("deviceId") Long deviceId,
            @Param("profileId") Long profileId,
            @Param("excludeCertificateId") Long excludeCertificateId,
            @Param("issuedBefore") OffsetDateTime issuedBefore);

    interface ProfileCorrelationCandidateView {
        String getCertificateXref();
        String getFingerprintSha1();
        String getIssuerDn();
        String getSerialNumber();
    }

    Optional<IotDeviceCertificate> findByEnrollmentId(Long enrollmentId);

    List<IotDeviceCertificate> findByEnrollmentIdIn(List<Long> enrollmentIds);

    /**
     * The newest still-usable certificate for one device and profile — the group's proof that
     * anything older has been replaced. Served by {@code idx_iot_device_certificate_renewal}.
     */
    @Query("""
            SELECT certificate FROM IotDeviceCertificate certificate
             WHERE certificate.organizationId = :organizationId
               AND certificate.deviceId = :deviceId
               AND certificate.profileId = :profileId
               AND certificate.status = 'ISSUED'
               AND certificate.certificateAuthority = false
               AND certificate.validTo > :now
             ORDER BY certificate.issuedAt DESC, certificate.id DESC
            """)
    List<IotDeviceCertificate> findNewestUsableInGroup(
            @Param("organizationId") Long organizationId,
            @Param("deviceId") Long deviceId,
            @Param("profileId") Long profileId,
            @Param("now") OffsetDateTime now,
            Pageable pageable);

    /**
     * The certificates of a set of enrollments, locked in primary-key order.
     *
     * <p>Locked here rather than left to the flush, because the flush order is the order rows came
     * back from an unordered read — and the check-in path locks the same rows by primary key. Two
     * writers taking the same certificates in different orders deadlock, and a rebind runs inside
     * a sync while nothing stops an operator asking for a check-in on the devices it is orphaning.
     * Acquiring the locks up front and in key order makes the order a property of this query
     * instead of an accident of the persistence context.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT certificate FROM IotDeviceCertificate certificate
             WHERE certificate.enrollmentId IN :enrollmentIds
             ORDER BY certificate.id
            """)
    List<IotDeviceCertificate> lockByEnrollmentIdIn(
            @Param("enrollmentIds") List<Long> enrollmentIds);

    /**
     * The certificate a renewal names as its predecessor, looked up the only way a stored
     * enrollment can: an enrollment records the prior issuer and serial but not the CA provider,
     * so the source scope stands in for it. Returns a list because the caller must refuse anything
     * but a single answer rather than guess which predecessor it meant.
     */
    @Query("""
            SELECT certificate FROM IotDeviceCertificate certificate
             WHERE certificate.organizationId = :organizationId
               AND certificate.deviceSourceId = :deviceSourceId
               AND certificate.issuerDn = :issuerDn
               AND certificate.serialNumber = :serialNumber
            """)
    List<IotDeviceCertificate> findBySourceScopedIssuerAndSerial(
            @Param("organizationId") Long organizationId,
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("issuerDn") String issuerDn,
            @Param("serialNumber") String serialNumber);

    /**
     * Certificates on this device that are still usable — not revoked and not past their validity.
     * A device holding one of these must stay in the inventory: hiding it would hide a credential
     * that is still trusted.
     */
    @Query("""
            SELECT COUNT(certificate) FROM IotDeviceCertificate certificate
             WHERE certificate.deviceId = :deviceId
               AND certificate.status <> 'REVOKED'
               AND certificate.validTo > :now
            """)
    long countUsableForDevice(@Param("deviceId") Long deviceId, @Param("now") OffsetDateTime now);

    Optional<IotDeviceCertificate> findByOrganizationIdAndCaProviderAndIssuerDnAndSerialNumber(
            Long organizationId, String caProvider, String issuerDn, String serialNumber);

    List<IotDeviceCertificate> findAllByOrganizationIdAndIssuerDnAndSerialNumber(
            Long organizationId, String issuerDn, String serialNumber);

    Optional<IotDeviceCertificate> findByOrganizationIdAndCertificateXref(
            Long organizationId, String certificateXref);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT certificate FROM IotDeviceCertificate certificate "
            + "WHERE certificate.organizationId = :organizationId "
            + "AND certificate.certificateXref = :certificateXref")
    Optional<IotDeviceCertificate> findByOrganizationIdAndCertificateXrefForUpdate(
            @Param("organizationId") Long organizationId,
            @Param("certificateXref") String certificateXref);

    /**
     * Locks one certificate by id, for a writer that must read its current status before deciding.
     * Two revocation operations can be active for one certificate — the Intune-sourced path accepts
     * a request without checking for an existing one — and their results are processed
     * independently, so without this the later writer can overwrite a confirmed revocation with a
     * failure from the other operation.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT certificate FROM IotDeviceCertificate certificate WHERE certificate.id = :id")
    Optional<IotDeviceCertificate> findByIdForUpdate(@Param("id") Long id);

    /**
     * Certificates by id, locked in key order, for a writer that decides from their current status.
     * Same reason as {@code findByIdForUpdate}: two revocation operations can be active for one
     * certificate, so a status read that is not under lock can be stale by the time it is written
     * back. Key order keeps it consistent with every other multi-row certificate lock here.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT certificate FROM IotDeviceCertificate certificate
             WHERE certificate.id IN :ids
             ORDER BY certificate.id
            """)
    List<IotDeviceCertificate> lockAllByIdIn(@Param("ids") Collection<Long> ids);

    List<IotDeviceCertificate> findAllByOrganizationIdAndCertificateXrefIn(
            Long organizationId, List<String> certificateXrefs);

    /**
     * The bounded window of certificates whose Intune profile is still unresolved.
     *
     * <p>Never-resolved rows come first, oldest first, so none waits forever. {@code NOT_FOUND} and
     * {@code AMBIGUOUS} are not terminal, so they stay candidates indefinitely; taking them second
     * and newest first stops a tenant that has accumulated a window's worth of permanently
     * unresolvable certificates from shutting out every certificate issued since. That matters
     * beyond tidiness: a certificate with no profile is excluded from renewal monitoring
     * altogether, so starving it here means it is never nudged and silently expires.
     */
    @Query("""
            SELECT c.certificateXref AS certificateXref,
                   c.fingerprintSha1 AS fingerprintSha1,
                   c.issuerDn AS issuerDn,
                   c.serialNumber AS serialNumber
              FROM IotDeviceCertificate c
              JOIN IotCertificateEnrollment e ON e.id = c.enrollmentId
             WHERE c.deviceSourceId = :deviceSourceId
               AND e.profileId IS NULL
               AND e.profileResolutionStatus IN ('PENDING_SYNC','NOT_FOUND','AMBIGUOUS')
             ORDER BY CASE WHEN e.profileResolutionStatus = 'PENDING_SYNC' THEN 0 ELSE 1 END,
                      CASE WHEN e.profileResolutionStatus = 'PENDING_SYNC' THEN c.id END ASC,
                      c.id DESC
            """)
    List<ProfileCorrelationCandidateView> findProfileCorrelationCandidates(
            @Param("deviceSourceId") Long deviceSourceId, Pageable pageable);

    List<IotDeviceCertificate> findAllByDeviceSourceIdAndCertificateXrefIn(
            Long deviceSourceId, List<String> certificateXrefs);

    /**
     * Certificate inventory search. Every filter is optional; a null one is not applied.
     * {@code validToAfter}/{@code validToBefore} implement the status and expiring-window
     * filters — {@code ISSUED}/{@code EXPIRING}/{@code EXPIRED}, and {@code expiringWithinDays},
     * are all just bounds on {@code valid_to}, resolved by the caller before this query runs.
     * {@code validToAfter} is exclusive and {@code validToBefore} is inclusive so a single
     * instant can never satisfy two adjacent bounds at once — this must match
     * {@link IotCertificateQueryService#displayStatus} exactly, or a row could match one
     * {@code status} filter while displaying a different one. See
     * {@link IotDeviceRepository the device search equivalent} for why the
     * {@code CAST(... AS String)} around each text parameter is load-bearing against Postgres —
     * the same problem hits the two {@code OffsetDateTime} parameters here, just via a bare
     * {@code ? IS NULL} check with no comparison to anchor its type, instead of a function call.
     * H2 (used by unit tests) infers the type happily either way; only real Postgres reproduces
     * "ERROR: could not determine data type of parameter" without the cast.
     */
    @Query("""
            SELECT c
            FROM IotDeviceCertificate c
            WHERE c.organizationId = :organizationId
              AND (:deviceId IS NULL OR c.deviceId = :deviceId)
              AND (:profileId IS NULL OR c.profileId = :profileId)
              AND (:deviceSourceId IS NULL OR c.deviceSourceId = :deviceSourceId)
              AND (:caProvider IS NULL OR c.caProvider = :caProvider)
              AND ((CAST(:validToAfter AS java.time.OffsetDateTime) IS NULL
                    AND CAST(:validToBefore AS java.time.OffsetDateTime) IS NULL)
                   OR c.status IN ('ISSUED','ISSUED_PENDING_NOTIFICATION'))
              AND (CAST(:validToAfter AS java.time.OffsetDateTime) IS NULL OR c.validTo > :validToAfter)
              AND (CAST(:validToBefore AS java.time.OffsetDateTime) IS NULL OR c.validTo <= :validToBefore)
              AND (:renewalState IS NULL OR c.renewalState = :renewalState)
              AND (:search IS NULL
                   OR LOWER(c.commonName) LIKE LOWER(CONCAT('%', CAST(:search AS String), '%'))
                   OR LOWER(c.serialNumber) LIKE LOWER(CONCAT('%', CAST(:search AS String), '%'))
                   OR LOWER(c.subjectDn) LIKE LOWER(CONCAT('%', CAST(:search AS String), '%'))
              )
            """)
    Page<IotDeviceCertificate> search(
            @Param("organizationId") Long organizationId,
            @Param("deviceId") Long deviceId,
            @Param("profileId") Long profileId,
            @Param("deviceSourceId") Long deviceSourceId,
            @Param("caProvider") String caProvider,
            @Param("validToAfter") OffsetDateTime validToAfter,
            @Param("validToBefore") OffsetDateTime validToBefore,
            @Param("renewalState") String renewalState,
            @Param("search") String search,
            Pageable pageable);
}
