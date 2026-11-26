// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditContext;
import com.certmanagement.audit.AuditErasure;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.service.audit.OrganizationAuditRecorder;
import com.certmanagement.service.scheduler.RegisteredJob;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

/**
 * Performs physical (hard) deletion of records that have been soft-deleted for longer
 * than the configured retention period.
 *
 * <h3>Deletion order (respects FK constraints)</h3>
 * <ol>
 *   <li>cert_manual_issuance_state  — references certificates via cert_xref</li>
 *   <li>renewal_schedule            — references certificates via certificate_xref</li>
 *   <li>certificate_events          — references certificates, ON DELETE RESTRICT</li>
 *   <li>certificates                — references user_domain_certificate</li>
 *   <li>user_domain_certificate     — references organizations</li>
 *   <li>credential_references       — references organizations</li>
 *   <li>users                       — references organizations; first, the audit_events rows they acted
 *       in are pseudonymised ({@link AuditErasure#eraseMembers})</li>
 *   <li>alerts                      — references organizations</li>
 * </ol>
 *
 * <p>Every other dependent of these tables cascades, sets null, or is purged above. A new table with
 * a restricting foreign key into any of them must be added here too, or the purge stops for every
 * organisation and the per-organisation catch reduces it to a log line.
 *
 * <p>The auto-purge job runs nightly at 03:00 UTC. It resolves the effective retention
 * period per organization (org override &gt; global setting) and hard-deletes records
 * older than that threshold.
 *
 * <h3>Kill switches</h3>
 * Every purge, scheduled or manual (org admin or super admin), is gated by two tiers:
 * <ol>
 *   <li>{@code certping.jobs.soft-delete-purge.enabled} — static env-var, restart to flip.</li>
 *   <li>{@link FeatureFlags#SOFT_DELETE_PURGE} — dynamic DB-backed kill switch via {@link FeatureFlagService}.</li>
 * </ol>
 * The scheduled job skips quietly while either is off; a manual purge is refused with 423.
 *
 * <p><b>COMPLIANCE-SENSITIVE:</b> disabling the feature flag for an extended period stops
 * hard-deletion entirely and can put retention SLAs out of compliance. Treat any disable
 * as an audited operation — short-window incident response only.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SoftDeletePurgeService {

    static final String JOB_NAME = "soft-delete-purge";

    private final GlobalSettingsService       globalSettingsService;
    private final OrganizationRepository      organizationRepository;
    private final CertificateRepository       certificateRepository;
    private final CertManualIssuanceStateRepository manualIssuanceStateRepository;
    private final RenewalScheduleRepository   renewalScheduleRepository;
    private final UserDomainCertRepository    userDomainCertRepository;
    private final CredentialReferenceRepository credentialReferenceRepository;
    private final UserRepository              userRepository;
    private final CertificateEventRepository  certificateEventRepository;
    private final AlertRepository             alertRepository;
    private final SchedulerExecutionPolicy    executionPolicy;
    private final TransactionTemplate          transactionTemplate;
    private final AuditErasure                auditErasure;
    private final OrganizationAuditRecorder   organizationAudit;

    // ------------------------------------------------------------------ //
    //  Scheduled auto-purge
    // ------------------------------------------------------------------ //

    /**
     * Nightly auto-purge job — 03:00 UTC by default, after expiry-mark (02:00) and before
     * expired-cert-soft-delete (04:00). See {@link SoftDeletePurgeService class-level docs}
     * for the compliance-sensitivity callout and the two-tier kill-switch behavior.
     *
     * <p>Per-drain {@code correlationId} mint mirrors {@code DrainRunner.runDrain}: every
     * org processed in this run carries the same {@code corr=corr-cron-soft-delete-purge-<uuid>}
     * in logs, so a single grep recovers the whole sweep. The prior MDC state is restored in
     * the {@code finally} block.
     */
    @RegisteredJob(JOB_NAME)
    @Scheduled(cron = "${certping.jobs.soft-delete-purge.cron}", zone = "UTC")
    public void runAutoPurge() {
        if (!purgeAllowed()) {
            log.info("[SoftDeletePurgeService] purging is switched off — skipping soft-delete-purge");
            return;
        }
        String correlationId = "corr-cron-soft-delete-purge-" + UUID.randomUUID();
        String parentMdcCorrelationId = MDC.get("correlationId");
        MDC.put("correlationId", correlationId);

        try {
            log.info("Starting scheduled soft-delete auto-purge...");
            List<Long> orgIds = organizationRepository.findAllOrgIds();

            int totalDeleted = 0;
            for (Long orgId : orgIds) {
                try {
                    int days = globalSettingsService.resolveRetentionDays(orgId);
                    // Through the template: a direct call would bypass the proxy and run the
                    // ordered DELETEs as separate transactions. CertPing acts, in the org's trail.
                    PurgeResult result;
                    try (AuditScope scope = AuditScope.system(JOB_NAME, orgId)) {
                        result = transactionTemplate.execute(status -> purgeOrganization(orgId, days));
                    }
                    totalDeleted += result.totalHardDeleted();
                    log.debug("Auto-purge org={}: deleted {} records (retention={}d)", orgId, result.totalHardDeleted(), days);
                } catch (FeatureDisabledException e) {
                    log.warn("Auto-purge stopped before org={}: {}", orgId, e.getMessage());
                    break;
                } catch (Exception e) {
                    log.error("Auto-purge failed for org={}: {}", orgId, e.getMessage(), e);
                }
            }
            log.info("Scheduled auto-purge complete. Total hard-deleted records: {}", totalDeleted);
        } finally {
            if (parentMdcCorrelationId != null) {
                MDC.put("correlationId", parentMdcCorrelationId);
            } else {
                MDC.remove("correlationId");
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Manual purge (triggered by org admin or super admin)
    // ------------------------------------------------------------------ //

    /**
     * Hard-deletes all soft-deleted records for one organization that are older than
     * {@code retentionDays}.
     *
     * @throws FeatureDisabledException if either purge kill switch is off
     */
    @Transactional
    public PurgeResult purgeOrganization(Long organizationId, int retentionDays) {
        assertPurgeAllowed();
        OffsetDateTime cutoff = OffsetDateTime.now(ZoneOffset.UTC).minusDays(retentionDays);
        log.info("Purging org={}, retentionDays={}, cutoff={}", organizationId, retentionDays, cutoff);

        int manualIssuance = manualIssuanceStateRepository.hardDeleteByOrganizationIdAndDeletedAtBefore(organizationId, cutoff);
        int renewalSched   = renewalScheduleRepository.hardDeleteByOrganizationIdAndUpdatedAtBefore(organizationId, cutoff);
        int certEvents     = certificateEventRepository.hardDeleteByOrganizationIdAndCertificateDeletedAtBefore(organizationId, cutoff);
        int certs          = certificateRepository.hardDeleteByOrganizationIdAndDeletedAtBefore(organizationId, cutoff);
        int udCerts        = userDomainCertRepository.hardDeleteByOrganizationIdAndDeletedAtBefore(organizationId, cutoff);
        int credentials    = credentialReferenceRepository.hardDeleteByOrganizationIdAndUpdatedAtBefore(organizationId, cutoff);
        // GDPR erasure: the audit rows these members acted in keep the rows but lose their names, in this
        // transaction, so a purge that rolls back leaves both as they were.
        auditErasure.eraseMembers(userRepository.findPurgeableUserIds(organizationId, cutoff));
        int users          = userRepository.hardDeleteByOrganizationIdAndUpdatedAtBefore(organizationId, cutoff);
        int alerts         = alertRepository.hardDeleteByOrganizationIdAndCreatedAtBefore(organizationId, cutoff);

        PurgeResult result = new PurgeResult(manualIssuance, renewalSched, certEvents, certs, udCerts,
                               credentials, users, alerts);
        // data_retention.purged, in this transaction. A sweep that deleted nothing leaves no row; a purge someone
        // asked for is recorded whatever it found.
        if (result.totalHardDeleted() > 0 || AuditContext.actor().type() != AuditActorType.SYSTEM) {
            organizationAudit.recordsPurged(organizationId, retentionDays, result.totalHardDeleted());
        }
        return result;
    }

    /**
     * Global purge across all organizations — resolves per-org retention and loops
     * {@link #purgeOrganization} for each one.  Intended for super-admin triggered purge only.
     */
    public GlobalPurgeResult purgeAll() {
        assertPurgeAllowed();
        List<Long> allOrgIds = organizationRepository.findAllOrgIds();
        int totalManualIssuance = 0, totalRenewalSched = 0;
        int totalCerts = 0, totalUdCerts = 0, totalCredentials = 0;
        int totalUsers = 0, totalAlerts = 0;
        int totalCertEvents = 0;

        for (Long orgId : allOrgIds) {
            try {
                int days = globalSettingsService.resolveRetentionDays(orgId);
                PurgeResult r;
                try (AuditScope scope = AuditScope.system(JOB_NAME, orgId)) {
                    r = transactionTemplate.execute(status -> purgeOrganization(orgId, days));
                }
                totalManualIssuance += r.manualIssuanceDeleted();
                totalRenewalSched   += r.renewalScheduleDeleted();
                totalCertEvents     += r.certificateEventsDeleted();
                totalCerts          += r.certificatesDeleted();
                totalUdCerts        += r.userDomainCertsDeleted();
                totalCredentials    += r.credentialsDeleted();
                totalUsers          += r.usersDeleted();
                totalAlerts         += r.alertsDeleted();
            } catch (FeatureDisabledException e) {
                log.warn("Global purge stopped before org={}: {}", orgId, e.getMessage());
                break;
            } catch (Exception e) {
                log.error("Global purge failed for org={}: {}", orgId, e.getMessage(), e);
            }
        }

        return new GlobalPurgeResult(totalManualIssuance, totalRenewalSched,
                totalCertEvents, totalCerts, totalUdCerts, totalCredentials,
                totalUsers, totalAlerts);
    }

    private void assertPurgeAllowed() {
        if (!purgeAllowed()) {
            throw new FeatureDisabledException(FeatureFlags.SOFT_DELETE_PURGE, "FEATURE_DISABLED",
                    "Purging soft-deleted records is switched off on this platform.");
        }
    }

    /**
     * Both kill switches, through the {@code soft-delete-purge} entry of
     * {@link com.certmanagement.service.scheduler.JobPolicy}: {@code certping.jobs.soft-delete-purge.enabled}
     * and {@link FeatureFlags#SOFT_DELETE_PURGE}.
     */
    private boolean purgeAllowed() {
        return executionPolicy.canRun(JOB_NAME);
    }

    // ------------------------------------------------------------------ //
    //  Result records
    // ------------------------------------------------------------------ //

    public record PurgeResult(int manualIssuanceDeleted,
                              int renewalScheduleDeleted,
                              int certificateEventsDeleted,
                              int certificatesDeleted,
                              int userDomainCertsDeleted,
                              int credentialsDeleted,
                              int usersDeleted,
                              int alertsDeleted) {
        public int totalHardDeleted() {
            return manualIssuanceDeleted + renewalScheduleDeleted
                    + certificateEventsDeleted + certificatesDeleted + userDomainCertsDeleted
                    + credentialsDeleted
                    + usersDeleted + alertsDeleted;
        }
    }

    public record GlobalPurgeResult(int manualIssuanceDeleted,
                                    int renewalScheduleDeleted,
                                    int certificateEventsDeleted,
                                    int certificatesDeleted,
                                    int userDomainCertsDeleted,
                                    int credentialsDeleted,
                                    int usersDeleted,
                                    int alertsDeleted) {
        public int totalHardDeleted() {
            return manualIssuanceDeleted + renewalScheduleDeleted
                    + certificateEventsDeleted + certificatesDeleted + userDomainCertsDeleted
                    + credentialsDeleted
                    + usersDeleted + alertsDeleted;
        }
    }
}
