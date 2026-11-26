// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.RenewalScheduleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface RenewalScheduleRepository extends JpaRepository<RenewalScheduleEntity, Long> {

    Optional<RenewalScheduleEntity> findByCertificateXref(String certificateXref);

    @Modifying
    @Query("UPDATE RenewalScheduleEntity r SET r.enabled = false " +
           "WHERE r.certificateXref = :xref AND r.isDeleted = false")
    int disableSchedule(@Param("xref") String xref);

    @Modifying
    @Query("UPDATE RenewalScheduleEntity r SET r.enabled = false, r.isDeleted = true, r.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE r.certificateXref = :xref AND r.isDeleted = false")
    int softDeleteByXref(@Param("xref") String xref);

    @Modifying
    @Query("UPDATE RenewalScheduleEntity r SET r.enabled = false, r.isDeleted = true, r.updatedAt = CURRENT_TIMESTAMP " +
           "WHERE r.certificateXref IN " +
           "(SELECT c.certificateXref FROM CertificateEntity c " +
           " JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId " +
           " WHERE udc.organizationId = :organizationId) " +
           "AND r.isDeleted = false")
    int softDeleteByOrganizationId(@Param("organizationId") Long organizationId);

    @Modifying
    @NativeQuery("DELETE FROM renewal_schedule rs " +
                   "USING user_domain_certificate udc, certificates c " +
                   "WHERE rs.certificate_xref = c.certificate_xref " +
                   "AND c.user_domain_cert_id = udc.id " +
                   "AND udc.organization_id = :organizationId " +
                   "AND rs.is_deleted = true AND rs.updated_at < :cutoff")
    int hardDeleteByOrganizationIdAndUpdatedAtBefore(
            @Param("organizationId") Long organizationId,
            @Param("cutoff") java.time.OffsetDateTime cutoff);

    @Modifying
    @NativeQuery("DELETE FROM renewal_schedule WHERE is_deleted = true AND updated_at < :cutoff")
    int hardDeleteAllWithUpdatedAtBefore(@Param("cutoff") java.time.OffsetDateTime cutoff);

    @Query("SELECT r FROM RenewalScheduleEntity r " +
           "WHERE r.enabled = true " +
           "AND r.renewalEligibleAt <= :now " +
           "AND (r.lastRenewalStatus IS NULL " +
           "OR r.lastRenewalStatus = 'SUCCESS' " +
           "OR (r.lastRenewalStatus = 'FAILED' " +
           "AND r.nextAttemptAt IS NOT NULL AND r.nextAttemptAt <= :now))")
    List<RenewalScheduleEntity> findEligibleForRenewal(@Param("now") OffsetDateTime now);

    /**
     * Worker-queue claim. Atomically locks and returns one eligible renewal_schedule row;
     * returns empty when nothing is available. Uses Postgres's {@code FOR UPDATE SKIP LOCKED}
     * so multiple pods cooperate on the same drain loop without ever contending on the same
     * row (each pod grabs a different row in parallel).
     *
     * <p>Eligibility:
     * <ul>
     *   <li>{@code enabled = true}</li>
     *   <li>{@code renewal_eligible_at <= now}</li>
     *   <li>{@code last_renewal_status} is NULL or SUCCESS, OR</li>
     *   <li>{@code last_renewal_status} FAILED, FEATURE_HOLD or DNS_KEY_EXPIRED_HOLD with an explicit, due
     *       {@code next_attempt_at}, OR</li>
     *   <li>{@code last_renewal_status = 'IN_PROGRESS'} but the row hasn't been touched since
     *       {@code stuckCutoff} while its certificate is not {@code RENEWING}, such as an Akamai re-issuance whose
     *       result was lost (a {@code RENEWING} certificate is ended by recover-stalled-renewals instead).</li>
     * </ul>
     *
     * <p>The lock is transactional — released when the caller's tx commits or rolls back.
     * On pod death mid-processing, Postgres detects the connection drop, rolls back the tx,
     * releases the lock automatically — another pod's next claim picks up the row.
     *
     * <p>ORDER BY {@code renewal_eligible_at} ensures the most-overdue certs are processed
     * first, regardless of which pod claims them.
     */
    // A RENEWING certificate has an attempt in flight, possibly as an agent retry scheduled days ahead on its
    // queue, so its schedule is never claimed: a second attempt would race the first at the CA. The attempt
    // ends with its result, or with recover-stalled-renewals once no agent can answer any more.
    @NativeQuery("""
        SELECT s.* FROM renewal_schedule s
          JOIN certificates c ON c.certificate_xref = s.certificate_xref
         WHERE s.enabled = true
           AND s.renewal_eligible_at <= :now
           AND c.status <> 'RENEWING'
           AND (
               s.last_renewal_status IS NULL
               OR s.last_renewal_status = 'SUCCESS'
               OR (s.last_renewal_status IN ('FAILED', 'FEATURE_HOLD', 'DNS_KEY_EXPIRED_HOLD')
                   AND s.next_attempt_at IS NOT NULL
                   AND s.next_attempt_at <= :now)
               OR (s.last_renewal_status = 'IN_PROGRESS' AND s.updated_at < :stuckCutoff)
           )
         ORDER BY s.renewal_eligible_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1
        """)
    Optional<RenewalScheduleEntity> claimOneEligible(
        @Param("now") OffsetDateTime now,
        @Param("stuckCutoff") OffsetDateTime stuckCutoff);

    /**
     * Retry-queue claim for retry-renewals: locks the earliest due failure of an enabled schedule whose certificate
     * is not renewing. First attempts and holds wait for the daily {@link #claimOneEligible} run. The first three
     * conditions are the predicate of {@code idx_renewal_schedule_retry_due} word for word, so the claim uses it.
     */
    @NativeQuery("""
        SELECT s.* FROM renewal_schedule s
          JOIN certificates c ON c.certificate_xref = s.certificate_xref
         WHERE s.last_renewal_status = 'FAILED' AND s.enabled AND NOT s.is_deleted
           AND s.next_attempt_at <= :now
           AND s.renewal_eligible_at <= :now
           AND c.status <> 'RENEWING'
         ORDER BY s.next_attempt_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT 1
        """)
    Optional<RenewalScheduleEntity> claimOneDueRetry(@Param("now") OffsetDateTime now);

    /**
     * Rearms parked failures, and holds for an expired CertPing DNS key, for the certificate configuration whose
     * DNS mapping was repaired; the repair starts their failure count again.
     */
    @Modifying
    @NativeQuery("""
        UPDATE renewal_schedule
           SET next_attempt_at = NOW(), consecutive_failures = 0, updated_at = NOW()
         WHERE domain_credential_config_id = :configId
           AND enabled = true
           AND is_deleted = false
           AND ((last_renewal_status = 'FAILED' AND next_attempt_at IS NULL)
                OR last_renewal_status = 'DNS_KEY_EXPIRED_HOLD')
        """)
    int rearmParkedFailuresByDomainCredentialConfigId(@Param("configId") Long configId);

    /**
     * Rearms every parked failure, and every hold for an expired CertPing DNS key, whose live DNS map references
     * an updated shared credential, and starts its failure count again.
     * The database performs one set-based update, so rotating a credential used by thousands
     * of certificates does not load or update schedules one row at a time.
     */
    @Modifying
    @NativeQuery("""
        UPDATE renewal_schedule s
           SET next_attempt_at = NOW(), consecutive_failures = 0, updated_at = NOW()
          FROM domain_credential_config dcc
         WHERE s.domain_credential_config_id = dcc.id
           AND s.enabled = true
           AND s.is_deleted = false
           AND ((s.last_renewal_status = 'FAILED' AND s.next_attempt_at IS NULL)
                OR s.last_renewal_status = 'DNS_KEY_EXPIRED_HOLD')
           AND dcc.is_deleted = false
           AND EXISTS (
               SELECT 1
                 FROM jsonb_each_text(COALESCE(dcc.dns_config, CAST('{}' AS jsonb))) AS dns_entry
                WHERE dns_entry.value = :credentialXref
           )
        """)
    int rearmParkedFailuresByDnsCredentialXref(
            @Param("credentialXref") String credentialXref);

    @Query("""
           SELECT DISTINCT r.certSecretHandle
           FROM RenewalScheduleEntity r
           WHERE r.certSecretHandle IS NOT NULL
             AND r.certSecretHandle <> ''
             AND EXISTS (
                 SELECT 1
                 FROM CertificateEntity c
                 JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
                 WHERE c.certificateXref = r.certificateXref
                   AND c.deletedAt IS NULL
                   AND udc.organizationId = :organizationId
             )
           """)
    List<String> findDistinctCertSecretHandlesByOrganizationId(@Param("organizationId") Long organizationId);

    @Query("""
           SELECT DISTINCT r.acmeAccountHandle
           FROM RenewalScheduleEntity r
           WHERE r.acmeAccountHandle IS NOT NULL
             AND r.acmeAccountHandle <> ''
             AND EXISTS (
                 SELECT 1
                 FROM CertificateEntity c
                 JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
                 WHERE c.certificateXref = r.certificateXref
                   AND c.deletedAt IS NULL
                   AND udc.organizationId = :organizationId
             )
           """)
    List<String> findDistinctAcmeAccountHandlesByOrganizationId(@Param("organizationId") Long organizationId);

    @Query("""
           SELECT DISTINCT r.caCredentialHandle
           FROM RenewalScheduleEntity r
           WHERE r.caCredentialHandle IS NOT NULL
             AND r.caCredentialHandle <> ''
             AND EXISTS (
                 SELECT 1
                 FROM CertificateEntity c
                 JOIN UserDomainCertEntity udc ON udc.id = c.userDomainCertId
                 WHERE c.certificateXref = r.certificateXref
                   AND c.deletedAt IS NULL
                   AND udc.organizationId = :organizationId
             )
           """)
    List<String> findDistinctCaCredentialHandlesByOrganizationId(@Param("organizationId") Long organizationId);
}
