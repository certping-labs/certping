// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.audit.AuditScope;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.CertIssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * Automatically soft-deletes certificates whose status is EXPIRED or REVOKED and have been
 * in that state for more than 24 hours.
 *
 * <p>Worker-queue pattern: {@code SchedulerJobs.expiryCleanup} (04:00 UTC by default) drains one
 * cert per transaction via {@link #tryProcessOneEligible()} through {@link DrainRunner}, which
 * applies the {@code expiry-cleanup} entry of {@link JobPolicy} (env switch plus the
 * {@code EXPIRED_CERT_SOFT_DELETE} kill switch), re-checks it every row, and bounds each run.
 * Multi-pod safe via Postgres's {@code SELECT … FOR UPDATE SKIP LOCKED}.
 *
 * <p>State marker: {@code certificates.deleted_at}. After soft-delete, deleted_at IS NOT
 * NULL so the eligibility query excludes the row.
 *
 * <p>Per-row work delegates to {@code CertIssuanceService.deleteRevoked} which cascades
 * the soft-delete (renewal_schedule, issuance state) and queues a {@code CERT_SECRET_DELETE_COMMAND}
 * to the agent to purge the PEM bundle from the client's KV.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@CronJobFor("expiry-cleanup")
public class CertExpiryCleanupService implements DrainableCron {

    private static final int CLEANUP_AGE_HOURS = 24;

    private final CertificateRepository certificateRepository;
    private final CertIssuanceService certIssuanceService;
    private final TransactionTemplate transactionTemplate;

    /**
     * Claims one EXPIRED/REVOKED cert older than the cutoff and soft-deletes it in a
     * single transaction (including the cascade to renewal_schedule and the queued agent
     * KV-delete).
     *
     * @return {@code true} if a cert was claimed (drain loop continues), {@code false}
     *         when no eligible certs remain.
     */
    @Override
    public boolean tryProcessOneEligible() {
        // A template rather than @Transactional: one transaction per claimed row, whatever proxying
        // the caller goes through.
        return Boolean.TRUE.equals(transactionTemplate.execute(status -> claimAndSoftDeleteOne()));
    }

    private boolean claimAndSoftDeleteOne() {
        OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minusHours(CLEANUP_AGE_HOURS);
        Optional<CertificateEntity> claimed = certificateRepository.claimOneExpiredOrRevokedForCleanup(cutoff);
        if (claimed.isEmpty()) {
            return false;
        }
        CertificateEntity cert = claimed.get();

        // CertPing removes it: the certificate.deleted row (source EXPIRY_CLEANUP) is its own, in this transaction.
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.CLEANUP_JOB, cert.getOrganizationId())) {
            certIssuanceService.deleteRevoked(cert.getOrganizationId(), cert.getCertificateXref());
            log.info("[CertExpiryCleanupService] Soft-deleted xref={}, organizationId={}",
                    cert.getCertificateXref(), cert.getOrganizationId());
        } catch (Exception e) {
            log.error("[CertExpiryCleanupService] Failed to soft-delete cert xref={}: {}",
                    cert.getCertificateXref(), e.getMessage(), e);
            // Rethrow so the tx rolls back — cert remains EXPIRED/REVOKED and will be
            // re-claimed on the next drain iteration (or next cron tick).
            throw e;
        }

        return true;
    }
}
