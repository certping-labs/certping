// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.audit.AuditScope;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.EventSource;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.NotificationPublisher;
import com.certmanagement.messaging.model.CertOwnSecretDeleteCommand;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.CertificateAuditRecorder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

/**
 * Marks certificates whose {@code valid_to < NOW()} as EXPIRED.
 *
 * <p>Worker-queue pattern: the cron drains one cert per transaction via
 * {@link #tryProcessOneEligible()} until no expired certs remain. Multi-pod safe via
 * Postgres's {@code SELECT … FOR UPDATE SKIP LOCKED}.
 *
 * <p>State marker: {@code certificates.status} transitions ACTIVE/RENEWING → EXPIRED.
 * The eligibility query filters {@code status IN ('ACTIVE','RENEWING')} so a processed
 * row drops out of the queue naturally.
 *
 * <p>Per-cert work in a single transaction: UPDATE status, INSERT event, disable
 * renewal_schedule, publish CERT_EXPIRED notification. The slow agent KV-delete is
 * deferred to post-commit so the DB tx commits before the network call.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@CronJobFor("mark-expired-certs")
public class CertExpiryMarkService implements DrainableCron {

    private final CertificateRepository      certificateRepository;
    private final CertificateEventRepository  certEventRepository;
    private final RenewalScheduleRepository   renewalScheduleRepository;
    private final NotificationPublisher       notificationPublisher;
    private final ObjectProvider<CertAgentPublisher> certAgentPublisher;
    private final OrgTypeResolver orgTypeResolver;
    /** Writes the expiry's audit row in this transaction, CertPing acting. */
    private final CertificateAuditRecorder certificateAudit;

    /**
     * Claims one expired cert and marks it EXPIRED in a single transaction.
     *
     * @return {@code true} if a cert was claimed (drain loop continues), {@code false}
     *         when no eligible certs remain.
     */
    @Override
    @Transactional
    public boolean tryProcessOneEligible() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        Optional<CertificateEntity> claimed = certificateRepository.claimOneExpiredCert(now);
        if (claimed.isEmpty()) {
            return false;
        }
        CertificateEntity cert = claimed.get();

        try {
            // 1. Status → EXPIRED
            certificateRepository.updateStatus(cert.getCertificateXref(), "EXPIRED");

            // 2. Audit event
            CertificateEventEntity event = CertificateEventEntity.builder()
                    .certificateXref(cert.getCertificateXref())
                    .organizationId(cert.getOrganizationId())
                    .eventType(CertEventType.CERT_EXPIRED.name())
                    .fromStatus(cert.getStatus())
                    .toStatus("EXPIRED")
                    .source(EventSource.SCHEDULER.value())
                    .build();
            certEventRepository.save(event);
            try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.EXPIRY_JOB, cert.getOrganizationId())) {
                certificateAudit.expired(cert);
            }

            // 3. Disable the cert's renewal schedule (idempotent; no-op if no schedule)
            renewalScheduleRepository.disableSchedule(cert.getCertificateXref());

            // 4. Publish CERT_EXPIRED notification (best-effort — notification failure does
            //    not roll back the status update)
            try {
                notificationPublisher.publish(
                        "CERT_EXPIRED",
                        cert.getOrganizationId().toString(),
                        cert.getCertificateXref(),
                        Map.of(
                                "domain",  cert.getDomain(),
                                "validTo", cert.getValidTo() != null ? cert.getValidTo().toString() : ""
                        )
                );
            } catch (Exception notifEx) {
                log.warn("[CertExpiryMarkService] Notification failed for xref={}: {}",
                        cert.getCertificateXref(), notifEx.getMessage());
            }

            // 5. Schedule the agent KV-delete to fire AFTER this tx commits. The agent
            //    publish is a network call (slow); doing it post-commit means the DB lock
            //    is released first and any failure during the publish doesn't affect the
            //    committed EXPIRED state.
            String path = cert.getCertSecretHandle();
            if (path != null && !path.isBlank()) {
                schedulePostCommitKvDelete(cert, path);
            }

            log.info("[CertExpiryMarkService] Marked EXPIRED: xref={}, domain={}, organizationId={}",
                    cert.getCertificateXref(), cert.getDomain(), cert.getOrganizationId());
        } catch (Exception e) {
            log.error("[CertExpiryMarkService] Failed to mark EXPIRED xref={}: {}",
                    cert.getCertificateXref(), e.getMessage(), e);
            // Rethrow so the tx rolls back — the row remains ACTIVE/RENEWING and will be
            // re-claimed on the next drain iteration (or next cron tick).
            throw e;
        }

        return true;
    }

    private void schedulePostCommitKvDelete(CertificateEntity cert, String certSecretHandle) {
        String org     = cert.getOrganizationId().toString();
        String orgType = orgTypeResolver.resolve(cert.getOrganizationId());
        String xref    = cert.getCertificateXref();
        Runnable task = () -> certAgentPublisher.ifAvailable(publisher -> {
            String requestId = "req-kvd-" + System.nanoTime();
            try {
                publisher.publishKvSecretDeleteCommand(
                        CertOwnSecretDeleteCommand.builder()
                                .requestId(requestId)
                                .correlationId(null)  // scheduler-driven, no upstream caller
                                .organizationId(org)
                                .orgType(orgType)
                                .certificateXref(xref)
                                .certSecretHandle(certSecretHandle)
                                .reason("CERT_EXPIRED")
                                .build());
            } catch (Exception e) {
                log.warn("[CertExpiryMarkService] Failed to publish CERT_OWN_SECRET_DELETE for xref={}: {}",
                        xref, e.getMessage());
            }
        });

        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override public void afterCommit() { task.run(); }
            });
        } else {
            // No tx context (e.g., test path) — run inline.
            task.run();
        }
    }
}
