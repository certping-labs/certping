// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CaProvider;
import jakarta.persistence.QueryHint;
import org.hibernate.jpa.HibernateHints;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {

    /**
     * Entity finders whose results reach the agent response consumer fetch {@code userDomainCert}:
     * it reads domain and organization with no session open. The native claim queries further
     * down run inside the schedulers' transactions and load it lazily.
     */
    @EntityGraph(attributePaths = "userDomainCert")
    @Query("SELECT c FROM CertificateEntity c WHERE c.certificateXref = :xref AND c.deletedAt IS NULL")
    Optional<CertificateEntity> findByCertificateXref(@Param("xref") String certificateXref);

    @EntityGraph(attributePaths = "userDomainCert")
    Optional<CertificateEntity> findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
           Long userDomainCertId,
           String status);

    @EntityGraph(attributePaths = "userDomainCert")
    @Query("SELECT c FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE c.certificateXref = :xref " +
           "AND udc.organizationId = :organizationId " +
           "AND c.deletedAt IS NULL")
    Optional<CertificateEntity> findByCertificateXrefAndOrganizationId(
            @Param("xref") String certificateXref,
            @Param("organizationId") Long organizationId);

    /** Bounded by {@code xrefs}, which callers take from one page of deployments. */
    @EntityGraph(attributePaths = "userDomainCert")
    @Query("SELECT c FROM CertificateEntity c " +
          "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
          "WHERE udc.organizationId = :organizationId " +
          "AND c.certificateXref IN :xrefs " +
          "AND c.deletedAt IS NULL")
    List<CertificateEntity> findByOrganizationIdAndCertificateXrefIn(
           @Param("organizationId") Long organizationId,
           @Param("xrefs") List<String> xrefs);

    interface CertificateXrefStatus {
        String getCertificateXref();
        String getStatus();
    }

    /**
     * Every non-deleted cert iteration of one domain (UDC), scoped to the caller's
     * organization, for the cascade-delete-domain flow to fan out a single-cert delete per row.
     * Bounded by one domain's live certificates.
     */
    @Query("SELECT c.certificateXref AS certificateXref, c.status AS status FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE c.userDomainCertId = :userDomainCertId " +
           "AND udc.organizationId = :organizationId " +
           "AND c.deletedAt IS NULL")
    List<CertificateXrefStatus> findActiveByUserDomainCertIdAndOrganizationId(
            @Param("userDomainCertId") Long userDomainCertId,
            @Param("organizationId") Long organizationId);

    @Query("SELECT CASE WHEN COUNT(c) > 0 THEN true ELSE false END " +
           "FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE c.certificateXref = :xref " +
           "AND udc.organizationId = :organizationId " +
           "AND c.deletedAt IS NULL")
    boolean existsByCertificateXrefAndOrganizationId(
            @Param("xref") String certificateXref,
            @Param("organizationId") Long organizationId);

    @Query("SELECT COUNT(c) FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE udc.organizationId = :organizationId " +
           "AND c.status IN :statuses " +
           "AND c.deletedAt IS NULL")
    long countByOrganizationIdAndStatusIn(
            @Param("organizationId") Long organizationId,
            @Param("statuses") List<String> statuses);

    @EntityGraph(attributePaths = "userDomainCert")
    @Query(value = "SELECT c FROM CertificateEntity c " +
          "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
          "WHERE udc.organizationId = :organizationId " +
          "AND c.deletedAt IS NULL " +
          "AND c.status <> 'RENEWAL_FAILED' " +
          "AND (:status IS NULL OR c.status = :status) " +
          "AND (:domainPattern IS NULL OR LOWER(udc.domain) LIKE :domainPattern) " +
          "AND c.createdAt = (" +
          "   SELECT MAX(c2.createdAt) FROM CertificateEntity c2 " +
          "   WHERE c2.userDomainCertId = c.userDomainCertId " +
          "   AND c2.deletedAt IS NULL " +
          "   AND c2.status <> 'RENEWAL_FAILED'" +
          ")",
          countQuery = "SELECT COUNT(c) FROM CertificateEntity c " +
                 "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
                 "WHERE udc.organizationId = :organizationId " +
                 "AND c.deletedAt IS NULL " +
                 "AND c.status <> 'RENEWAL_FAILED' " +
                 "AND (:status IS NULL OR c.status = :status) " +
                 "AND (:domainPattern IS NULL OR LOWER(udc.domain) LIKE :domainPattern) " +
                 "AND c.createdAt = (" +
                 "   SELECT MAX(c2.createdAt) FROM CertificateEntity c2 " +
                 "   WHERE c2.userDomainCertId = c.userDomainCertId " +
                 "   AND c2.deletedAt IS NULL " +
                 "   AND c2.status <> 'RENEWAL_FAILED'" +
                 ")")
    Page<CertificateEntity> findLatestByOrganizationAndFilters(
           @Param("organizationId") Long organizationId,
           @Param("status") String status,
           @Param("domainPattern") String domainPattern,
           Pageable pageable);

    @EntityGraph(attributePaths = "userDomainCert")
    @Query("SELECT c FROM CertificateEntity c " +
          "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
          "WHERE udc.organizationId = :organizationId " +
          "AND c.userDomainCertId = :userDomainCertId " +
          "AND c.deletedAt IS NULL")
    Page<CertificateEntity> findHistoryByOrganizationAndUserDomainCertId(
           @Param("organizationId") Long organizationId,
           @Param("userDomainCertId") Long userDomainCertId,
           Pageable pageable);

    @Modifying
    @Query("UPDATE CertificateEntity c SET c.status = :status, c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.certificateXref = :xref AND c.deletedAt IS NULL")
    int updateStatus(@Param("xref") String certificateXref, @Param("status") String status);

    @Query("SELECT COUNT(c) FROM CertificateEntity c " +
           "WHERE (c.acmeAccountHandle = :secretHandle OR c.caCredentialHandle = :secretHandle) " +
           "AND c.status NOT IN ('DELETED', 'EXPIRED', 'RENEW_SUCCESS') AND c.deletedAt IS NULL")
    long countActiveCertificatesReferencingKvPath(@Param("secretHandle") String secretHandle);

    @Query("SELECT c.status, COUNT(c) FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE udc.organizationId = :organizationId AND c.deletedAt IS NULL " +
           "GROUP BY c.status")
    List<Object[]> countByStatusForOrganization(@Param("organizationId") Long organizationId);

    @Query("SELECT COUNT(c) FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE udc.organizationId = :organizationId " +
           "AND udc.isDeleted = false " +
           "AND c.deletedAt IS NULL " +
           "AND c.status = 'ACTIVE' " +
           "AND c.validTo IS NOT NULL " +
           "AND c.validTo >= :from AND c.validTo <= :to")
    long countExpiringBetween(
            @Param("organizationId") Long organizationId,
            @Param("from") OffsetDateTime from,
            @Param("to") OffsetDateTime to);

    /**
     * Assistant-safe projection for expiring ACTIVE certs (no secret/credential handles).
     * ACTIVE includes a previous cert that remains ACTIVE after a renewal failure — desired.
     */
    interface ExpiringCertificateRow {
        String getDomain();
        String getCertificateXref();
        OffsetDateTime getValidTo();
        String getStatus();
        CaProvider getCaProvider();
    }

    /**
     * Slice of ACTIVE certs whose {@code validTo} falls in {@code [from, to]} for the org.
     * Soft-delete on {@code CertificateEntity} is via {@code @Where}; UDC soft-delete is explicit
     * because ad-hoc JOIN bypasses {@code UserDomainCertEntity}'s {@code @Where}.
     * Stable order for paging ties: {@code validTo ASC, id ASC}. Prefer {@link Slice} over
     * {@link Page} for the short assistant window (no total-count query). Callers should pass
     * a UTC window aligned with the dashboard ({@code now} + N days), not midnight-to-midnight.
     */
    @Query("""
           SELECT udc.domain AS domain, c.certificateXref AS certificateXref,
                  c.validTo AS validTo, c.status AS status, c.caProvider AS caProvider
           FROM CertificateEntity c
           JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
           WHERE udc.organizationId = :organizationId
                  AND udc.isDeleted = false
                  AND c.status = 'ACTIVE'
                  AND c.validTo IS NOT NULL
                  AND c.validTo >= :from AND c.validTo <= :to
           ORDER BY c.validTo ASC, c.id ASC
           """)
    Slice<ExpiringCertificateRow> findExpiringBetween(
            @Param("organizationId") Long organizationId,
            @Param("from") OffsetDateTime from,
            @Param("to") OffsetDateTime to,
            Pageable pageable);

    /**
     * These three are unbounded by design: the agent deep health check verifies every Key Vault
     * path the organization's certificates use, and sends them in chunks. Distinct strings only.
     */
    @Query("""
       SELECT DISTINCT c.certSecretHandle
       FROM CertificateEntity c
       JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
       WHERE c.certSecretHandle IS NOT NULL
              AND c.certSecretHandle <> ''
              AND c.deletedAt IS NULL
              AND udc.organizationId = :organizationId
       """)
    List<String> findDistinctCertSecretHandlesByOrganizationId(@Param("organizationId") Long organizationId);

    @Query("""
       SELECT DISTINCT c.acmeAccountHandle
       FROM CertificateEntity c
       JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
       WHERE c.acmeAccountHandle IS NOT NULL
              AND c.acmeAccountHandle <> ''
              AND c.deletedAt IS NULL
              AND udc.organizationId = :organizationId
       """)
    List<String> findDistinctAcmeAccountHandlesByOrganizationId(@Param("organizationId") Long organizationId);

    @Query("""
       SELECT DISTINCT c.caCredentialHandle
       FROM CertificateEntity c
       JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
       WHERE c.caCredentialHandle IS NOT NULL
              AND c.caCredentialHandle <> ''
              AND c.deletedAt IS NULL
              AND udc.organizationId = :organizationId
       """)
    List<String> findDistinctCaCredentialHandlesByOrganizationId(@Param("organizationId") Long organizationId);

    @Modifying
    @Query("UPDATE CertificateEntity c " +
           "SET c.status = 'DELETED', c.deletedAt = CURRENT_TIMESTAMP, c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.certificateXref = :xref AND c.deletedAt IS NULL " +
           "AND EXISTS (SELECT 1 FROM UserDomainCertEntity udc " +
           "WHERE udc.id = c.userDomainCertId AND udc.organizationId = :organizationId)")
    int softDelete(@Param("xref") String certificateXref, @Param("organizationId") Long organizationId);

    @Modifying
    @Query("UPDATE CertificateEntity c " +
           "SET c.status = 'REVOKED', c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.certificateXref = :xref AND c.deletedAt IS NULL " +
           "AND EXISTS (SELECT 1 FROM UserDomainCertEntity udc " +
           "WHERE udc.id = c.userDomainCertId AND udc.organizationId = :organizationId)")
    int revokeCert(@Param("xref") String certificateXref, @Param("organizationId") Long organizationId);

    /**
     * Moves a certificate of {@code organizationId} into {@code RENEWING} only from a status a renewal may start
     * from, so two renewals (a manual one and the scheduler's) can never both start: the second finds the first's
     * {@code RENEWING} and changes nothing.
     *
     * @return 1 when the certificate moved, 0 when it was not in a renewable status
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE CertificateEntity c SET c.status = 'RENEWING', c.updatedAt = :updatedAt " +
           "WHERE c.certificateXref = :xref AND c.deletedAt IS NULL " +
           "AND c.status IN ('ACTIVE', 'EXPIRED') " +
           "AND EXISTS (SELECT 1 FROM UserDomainCertEntity udc " +
           "WHERE udc.id = c.userDomainCertId AND udc.organizationId = :organizationId)")
    int tryMarkRenewing(@Param("xref") String certificateXref,
                        @Param("organizationId") Long organizationId,
                        @Param("updatedAt") OffsetDateTime updatedAt);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE CertificateEntity c SET c.status = 'REVOKING', c.updatedAt = :updatedAt " +
           "WHERE c.certificateXref = :xref AND c.deletedAt IS NULL " +
           "AND c.status IN ('ACTIVE', 'REVOCATION_FAILED') " +
           "AND EXISTS (SELECT 1 FROM UserDomainCertEntity udc " +
           "WHERE udc.id = c.userDomainCertId AND udc.organizationId = :organizationId)")
    int tryMarkRevoking(@Param("xref") String certificateXref,
                        @Param("organizationId") Long organizationId,
                        @Param("updatedAt") OffsetDateTime updatedAt);

    /**
     * Worker-queue claim for mark-expired-certs. Locks one expired cert (ACTIVE/RENEWING past
     * validTo) for exclusive processing. Re-claim after commit is prevented by the
     * {@code status='EXPIRED'} state marker which the WHERE clause excludes.
     */
    @NativeQuery("""
        SELECT * FROM certificates
         WHERE status IN ('ACTIVE', 'RENEWING')
           AND valid_to IS NOT NULL
           AND valid_to < :now
           AND deleted_at IS NULL
         ORDER BY valid_to ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1
        """)
    Optional<CertificateEntity> claimOneExpiredCert(@Param("now") OffsetDateTime now);

    /**
     * Worker-queue claim for recover-stalled-renewals. Locks the certificate whose renewal has been in flight longest,
     * once it started before {@code cutoff}. The start is the newest {@code PENDING} draft's creation on the same
     * domain, which nothing else writes; a certificate without a draft falls back to its own {@code updated_at}.
     * Ending the attempt takes the certificate out of {@code RENEWING}, so it is not claimed again.
     */
    @NativeQuery("""
        SELECT c.* FROM certificates c
          LEFT JOIN LATERAL (
               SELECT d.created_at FROM certificates d
                WHERE d.user_domain_cert_id = c.user_domain_cert_id
                  AND d.status = 'PENDING'
                  AND d.deleted_at IS NULL
                ORDER BY d.created_at DESC
                LIMIT 1) draft ON TRUE
         WHERE c.status = 'RENEWING'
           AND c.deleted_at IS NULL
           AND COALESCE(draft.created_at, c.updated_at) < :cutoff
         ORDER BY COALESCE(draft.created_at, c.updated_at) ASC
         FOR UPDATE OF c SKIP LOCKED
         LIMIT 1
        """)
    Optional<CertificateEntity> claimOneStalledRenewal(@Param("cutoff") OffsetDateTime cutoff);

    /**
     * Worker-queue claim for cert-expiry-cleanup. Locks one EXPIRED or REVOKED cert
     * older than the cutoff for exclusive soft-delete. Re-claim after commit is
     * prevented by the {@code deleted_at IS NULL} state marker (deleteRevoked sets
     * deleted_at).
     *
     * <p>REVOKED is auto-cleaned-up here AFTER the 24-hour grace window so the user
     * has a chance to see the revocation outcome in the UI and trigger an explicit
     * cert-delete or user-domain-cert-delete first. The immediate auto-soft-delete
     * on the revocation response is intentionally OFF — see CertResponseProcessor.
     */
    @NativeQuery("""
        SELECT * FROM certificates
         WHERE status IN ('EXPIRED', 'REVOKED')
           AND updated_at < :cutoff
           AND deleted_at IS NULL
         ORDER BY updated_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1
        """)
    Optional<CertificateEntity> claimOneExpiredOrRevokedForCleanup(@Param("cutoff") OffsetDateTime cutoff);

    /**
     * Worker-queue claim for trigger-expiry-alerts. Locks one ACTIVE cert in the expiry
     * window that hasn't been alerted in the last 24h. Re-claim is prevented by the
     * {@code last_alerted_at} update which moves the row past the alertCutoff filter.
     */
    @NativeQuery("""
        SELECT * FROM certificates
         WHERE status = 'ACTIVE'
           AND valid_to IS NOT NULL
           AND valid_to >= :now
           AND valid_to <= :horizon
           AND deleted_at IS NULL
           AND (last_alerted_at IS NULL OR last_alerted_at < :alertCutoff)
         ORDER BY valid_to ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1
        """)
    Optional<CertificateEntity> claimOneExpiringActiveForAlert(
            @Param("now")         OffsetDateTime now,
            @Param("horizon")     OffsetDateTime horizon,
            @Param("alertCutoff") OffsetDateTime alertCutoff);

    @Modifying
    @Query("UPDATE CertificateEntity c " +
           "SET c.status = 'DELETED', c.deletedAt = CURRENT_TIMESTAMP, c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.deletedAt IS NULL " +
           "AND EXISTS (SELECT 1 FROM UserDomainCertEntity udc " +
           "WHERE udc.id = c.userDomainCertId AND udc.organizationId = :organizationId)")
    int softDeleteAllByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Finds the most-recently-created non-deleted certificate for a UDC that has the given
     * specialCertificateType and status. Used to locate an active Akamai-special cert before
     * deciding whether to deploy directly or trigger a new Akamai-specific issuance.
     */
    @EntityGraph(attributePaths = "userDomainCert")
    @Query("SELECT c FROM CertificateEntity c " +
           "WHERE c.userDomainCertId = :udcId " +
           "AND c.specialCertificateType = :specialType " +
           "AND c.status = :status " +
           "AND c.deletedAt IS NULL " +
           "ORDER BY c.createdAt DESC")
    Optional<CertificateEntity> findTopByUdcIdAndSpecialTypeAndStatus(
            @Param("udcId") Long userDomainCertId,
            @Param("specialType") String specialCertificateType,
            @Param("status") String status);

    /** Alias for backward compatibility with older service/tests naming. */
    @Modifying
    @Query("UPDATE CertificateEntity c " +
           "SET c.status = 'DELETED', c.deletedAt = CURRENT_TIMESTAMP, c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.deletedAt IS NULL " +
           "AND EXISTS (SELECT 1 FROM UserDomainCertEntity udc " +
           "WHERE udc.id = c.userDomainCertId AND udc.organizationId = :organizationId)")
    int softDeleteByOrganizationId(@Param("organizationId") Long organizationId);

    interface CertificateKvPath {
        String getCertificateXref();
        String getCertSecretHandle();
    }

    /**
     * Unbounded by design: organization deletion must send a Key Vault delete for every live
     * certificate's secret. Two strings per row, no entity.
     */
    @Query("SELECT c.certificateXref AS certificateXref, c.certSecretHandle AS certSecretHandle " +
           "FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE udc.organizationId = :organizationId " +
           "AND c.deletedAt IS NULL " +
           "AND c.certSecretHandle IS NOT NULL AND c.certSecretHandle <> ''")
    List<CertificateKvPath> findActiveWithKvPathByOrganizationId(
            @Param("organizationId") Long organizationId);

    @Modifying
    @Query("UPDATE CertificateEntity c SET c.lastAlertedAt = :alertedAt, c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.certificateXref = :xref AND c.deletedAt IS NULL")
    int updateLastAlertedAt(@Param("xref") String certificateXref,
                            @Param("alertedAt") OffsetDateTime alertedAt);

    /** {@link #updateLastAlertedAt} for a pass that sent an alert: also records the threshold it was for. */
    @Modifying
    @Query("UPDATE CertificateEntity c SET c.lastAlertedAt = :alertedAt, " +
           "c.expiryAlertThresholdDays = :thresholdDays, c.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE c.certificateXref = :xref AND c.deletedAt IS NULL")
    int recordExpiryAlert(@Param("xref") String certificateXref,
                          @Param("alertedAt") OffsetDateTime alertedAt,
                          @Param("thresholdDays") int thresholdDays);

    // ------------------------------------------------------------------ //
    //  Hard-delete (physical purge)
    // ------------------------------------------------------------------ //

    @Modifying
    @NativeQuery("DELETE FROM certificates c WHERE c.deleted_at IS NOT NULL AND c.deleted_at < :cutoff " +
                   "AND EXISTS (SELECT 1 FROM user_domain_certificate udc " +
                   "WHERE udc.id = c.user_domain_cert_id AND udc.organization_id = :organizationId)")
    int hardDeleteByOrganizationIdAndDeletedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") OffsetDateTime cutoff);

    @Modifying
    @NativeQuery("DELETE FROM certificates c WHERE c.deleted_at IS NOT NULL AND c.deleted_at < :cutoff")
    int hardDeleteAllWithDeletedAtBefore(@Param("cutoff") OffsetDateTime cutoff);

    /**
     * Returns true if a non-deleted certificate for the given organization has been
     * deployed to the specified provider resource ID (e.g. an ACM certificate ARN).
     * Used by DiscoveryService to determine whether a discovered cert is CertPing-managed.
     */
    @Query("SELECT CASE WHEN COUNT(c) > 0 THEN true ELSE false END " +
           "FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE udc.organizationId = :organizationId " +
           "AND c.targetResourceId = :targetResourceId " +
           "AND c.deletedAt IS NULL")
    boolean existsByOrganizationIdAndTargetResourceId(
            @Param("organizationId") Long organizationId,
            @Param("targetResourceId") String targetResourceId);

    /**
     * One row per distinct (algorithm, key size, curve, key usage) among the org's current certs: the newest
     * issued certificate of each domain lineage, so renewals and reissues do not add to the totals.
     */
    interface PqcAlgorithmCount {
        String getPublicKeyAlgorithm();
        Integer getKeySize();
        String getCurve();
        String getKeyUsage();
        long getCount();
    }

    /** The columns the PQC readiness detail rows are built from; no entity is loaded. */
    interface PqcCertificateRow {
        String getCertificateXref();
        String getCommonName();
        String getDomain();
        String getSignatureAlgorithm();
        String getPublicKeyAlgorithm();
        Integer getKeySize();
        String getCurve();
        String getKeyUsage();
    }

    @Query("""
       SELECT c.publicKeyAlgorithm AS publicKeyAlgorithm, c.keySize AS keySize,
              m.publicKeyCurve AS curve, m.keyUsage AS keyUsage, COUNT(c) AS count
       FROM CertificateEntity c
       JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
       LEFT JOIN CertificateCryptoMetadataEntity m ON m.certificateXref = c.certificateXref
       WHERE udc.organizationId = :organizationId
              AND c.deletedAt IS NULL
              AND c.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
              AND NOT EXISTS (
                  SELECT 1 FROM CertificateEntity n
                  WHERE n.userDomainCertId = c.userDomainCertId
                    AND n.deletedAt IS NULL
                    AND n.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
                    AND (n.createdAt > c.createdAt OR (n.createdAt = c.createdAt AND n.id > c.id)))
       GROUP BY c.publicKeyAlgorithm, c.keySize, m.publicKeyCurve, m.keyUsage
       ORDER BY c.publicKeyAlgorithm, c.keySize, m.publicKeyCurve, m.keyUsage
       """)
    List<PqcAlgorithmCount> countPqcAlgorithmsByOrganizationId(@Param("organizationId") Long organizationId);

    /**
     * Paged rows for the PQC certificate list. {@code algorithmKeys} (nullable) restricts to certs whose
     * {@code algorithm|keySize|curve} key, with empty strings for null parts, is in the collection.
     */
    @Query(value = """
       SELECT c.certificateXref AS certificateXref, m.commonName AS commonName, udc.domain AS domain,
              c.signatureAlgorithm AS signatureAlgorithm, c.publicKeyAlgorithm AS publicKeyAlgorithm,
              c.keySize AS keySize, m.publicKeyCurve AS curve, m.keyUsage AS keyUsage
       FROM CertificateEntity c
       JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
       LEFT JOIN CertificateCryptoMetadataEntity m ON m.certificateXref = c.certificateXref
       WHERE udc.organizationId = :organizationId
              AND c.deletedAt IS NULL
              AND c.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
              AND NOT EXISTS (
                  SELECT 1 FROM CertificateEntity n
                  WHERE n.userDomainCertId = c.userDomainCertId
                    AND n.deletedAt IS NULL
                    AND n.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
                    AND (n.createdAt > c.createdAt OR (n.createdAt = c.createdAt AND n.id > c.id)))
              AND (:algorithmKeys IS NULL OR CONCAT(COALESCE(c.publicKeyAlgorithm, ''), '|',
                         COALESCE(CAST(c.keySize AS String), ''), '|',
                         COALESCE(m.publicKeyCurve, '')) IN :algorithmKeys)
       """,
       countQuery = """
       SELECT COUNT(c) FROM CertificateEntity c
       JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
       LEFT JOIN CertificateCryptoMetadataEntity m ON m.certificateXref = c.certificateXref
       WHERE udc.organizationId = :organizationId
              AND c.deletedAt IS NULL
              AND c.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
              AND NOT EXISTS (
                  SELECT 1 FROM CertificateEntity n
                  WHERE n.userDomainCertId = c.userDomainCertId
                    AND n.deletedAt IS NULL
                    AND n.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
                    AND (n.createdAt > c.createdAt OR (n.createdAt = c.createdAt AND n.id > c.id)))
              AND (:algorithmKeys IS NULL OR CONCAT(COALESCE(c.publicKeyAlgorithm, ''), '|',
                         COALESCE(CAST(c.keySize AS String), ''), '|',
                         COALESCE(m.publicKeyCurve, '')) IN :algorithmKeys)
       """)
    Page<PqcCertificateRow> findPqcRowsByOrganizationId(
            @Param("organizationId") Long organizationId,
            @Param("algorithmKeys") Collection<String> algorithmKeys,
            Pageable pageable);

    /** Projection pairing a certificate's serial number with its xref. */
    interface SerialXref {
        String getSerialNumber();
        String getCertificateXref();
    }

    /**
     * Scrolls (serialNumber, certificateXref) for the org's non-deleted certs, so discovery can
     * tell which discovered certs CertPing issued and link them to the certificate.
     *
     * <p>Serial numbers are the most reliable cross-reference: they are independent of where
     * the cert is deployed and of which CA issued it. Cloud providers report them in other
     * textual forms, so callers normalize both sides in Java (strip separators, upper-case,
     * drop leading zeros), which is why the scan cannot be narrowed in SQL. Callers keep only the
     * rows matching the serials they hold, so memory is bounded by their input, not the org.
     * Must be consumed inside a transaction and closed.
     */
    @QueryHints(@QueryHint(name = HibernateHints.HINT_FETCH_SIZE, value = "500"))
    @Query("SELECT c.serialNumber AS serialNumber, c.certificateXref AS certificateXref " +
           "FROM CertificateEntity c " +
           "JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           "WHERE udc.organizationId = :organizationId " +
           "AND c.serialNumber IS NOT NULL " +
           "AND c.deletedAt IS NULL")
    Stream<SerialXref> streamSerialNumberAndXrefByOrganizationId(@Param("organizationId") Long organizationId);

    /** Everything a CBOM component is built from, for one certificate; no entity is loaded. */
    interface CbomCertificateRow {
        String getCertificateXref();
        String getDomain();
        String getIssuer();
        String getSerialNumber();
        String getFingerprintSha256();
        OffsetDateTime getValidFrom();
        OffsetDateTime getValidTo();
        String getSignatureAlgorithm();
        String getPublicKeyAlgorithm();
        Integer getKeySize();
        CaProvider getCaProvider();
        String getSignatureAlgorithmOid();
        String getSubjectDn();
        String getCommonName();
        String getPublicKeyCurve();
        String getKeyUsage();
        String getExtendedKeyUsage();
        String getSubjectKeyIdentifier();
        String getAuthorityKeyIdentifier();
    }

    /**
     * Scrolls the org's current certificates (newest issued per domain, as the PQC report counts) with their crypto metadata. Must be consumed inside a
     * read-only transaction and closed; the fetch size keeps the driver from buffering the result set.
     */
    @QueryHints(@QueryHint(name = HibernateHints.HINT_FETCH_SIZE, value = "500"))
    @Query("""
       SELECT c.certificateXref AS certificateXref, udc.domain AS domain, c.issuer AS issuer,
              c.serialNumber AS serialNumber, c.fingerprintSha256 AS fingerprintSha256,
              c.validFrom AS validFrom, c.validTo AS validTo,
              c.signatureAlgorithm AS signatureAlgorithm, c.publicKeyAlgorithm AS publicKeyAlgorithm,
              c.keySize AS keySize, c.caProvider AS caProvider,
              m.signatureAlgorithmOid AS signatureAlgorithmOid, m.subjectDn AS subjectDn,
              m.commonName AS commonName, m.publicKeyCurve AS publicKeyCurve, m.keyUsage AS keyUsage,
              m.extendedKeyUsage AS extendedKeyUsage, m.subjectKeyIdentifier AS subjectKeyIdentifier,
              m.authorityKeyIdentifier AS authorityKeyIdentifier
       FROM CertificateEntity c
       JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
       LEFT JOIN CertificateCryptoMetadataEntity m ON m.certificateXref = c.certificateXref
       WHERE udc.organizationId = :organizationId
              AND c.deletedAt IS NULL
              AND c.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
              AND NOT EXISTS (
                  SELECT 1 FROM CertificateEntity n
                  WHERE n.userDomainCertId = c.userDomainCertId
                    AND n.deletedAt IS NULL
                    AND n.status IN ('ACTIVE', 'RENEWING', 'EXPIRED', 'REVOKING', 'REVOKED', 'REVOCATION_FAILED')
                    AND (n.createdAt > c.createdAt OR (n.createdAt = c.createdAt AND n.id > c.id)))
       ORDER BY c.id
       """)
    Stream<CbomCertificateRow> streamCbomRowsByOrganizationId(@Param("organizationId") Long organizationId);
}
