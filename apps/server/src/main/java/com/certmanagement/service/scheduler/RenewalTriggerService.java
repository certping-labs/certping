// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.enums.EventSource;
import com.certmanagement.enums.RenewalStatus;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.PublishOutcome;
import com.certmanagement.messaging.model.CertRenewalCommand;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.exception.MissingDnsCredentialConfigurationException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import com.certmanagement.service.cert.AkamaiSpecialIssuanceService;
import com.certmanagement.service.cert.CertPingDnsKeys;
import com.certmanagement.service.cert.CertificateStatusValidator;
import com.certmanagement.service.cert.CredentialReferenceService;
import com.certmanagement.service.cert.RenewalDraftHelper;
import com.certmanagement.service.cert.RenewalRetryPolicy;
import com.certmanagement.service.cert.SanDomainHelper;
import com.certmanagement.util.MdcIds;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Worker-queue renewal trigger.
 *
 * <p>The cron entry-point in {@link SchedulerJobs} drains the eligible-row queue by calling
 * {@link #tryProcessOneEligible()} repeatedly until it returns {@code false}. Each call:
 * <ol>
 *   <li>Atomically claims one eligible {@code renewal_schedule} row via Postgres's
 *       {@code SELECT … FOR UPDATE SKIP LOCKED LIMIT 1}.</li>
 *   <li>Processes the cert (build draft, write state markers, publish CERT_RENEWAL).</li>
 *   <li>Commits the per-cert transaction; the row lock releases.</li>
 * </ol>
 *
 * <p>Multiple pods cooperate naturally — Postgres's row locks ensure two pods never grab the
 * same row, and parallel pods divide work via {@code SKIP LOCKED}. No leader, no heartbeat.
 *
 * <p>Failure tolerance:
 * <ul>
 *   <li><b>Pod death mid-processing</b>: Postgres detects the dead connection within seconds,
 *       rolls back the tx, releases the row lock. Another pod's next claim picks it up.</li>
 *   <li><b>Permanent response loss</b>: a {@code RENEWING} certificate is released by
 *       {@link StalledRenewalRecoveryService} after {@link AbandonedRenewalCleanup#IN_FLIGHT_HORIZON}. A row
 *       {@code IN_PROGRESS} for that long without a {@code RENEWING} certificate (such as an Akamai re-issuance) is
 *       claimed again here, and {@link AbandonedRenewalCleanup} ends its attempt before the retry runs.</li>
 *   <li><b>Per-cert failure</b>: caught inside the per-cert tx; schedule marked FAILED,
 *       draft marked RENEWAL_FAILED. The tx still commits with the FAILED markers so the
 *       row isn't re-claimed in an infinite loop.</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
@CronJobFor("trigger-renewals")
public class RenewalTriggerService implements DrainableCron {

    /** How often a schedule held for an expired CertPing DNS key is checked again; a renewed key rearms it at once. */
    static final Duration DNS_KEY_HOLD_RECHECK = Duration.ofHours(1);
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateEventRepository certEventRepository;
    private final DomainCredentialConfigRepository domainCredConfigRepository;
    private final UserDomainCertRepository udcRepository;
    private final CredentialReferenceService credentialService;
    private final CertAgentPublisher publisher;
    private final CertificateStatusValidator certificateStatusValidator;
    private final RenewalDraftHelper renewalDraftHelper;
    private final FeatureFlagService featureFlagService;
    private final AkamaiSpecialIssuanceService akamaiSpecialIssuanceService;
    private final OrgTypeResolver orgTypeResolver;
    /** Writes CertPing's renewal rows in each certificate's transaction. */
    private final CertificateAuditRecorder certificateAudit;
    private final FeatureFlagResolver featureFlagResolver;
    private final AbandonedRenewalCleanup abandonedRenewalCleanup;
    private final CertPingDnsKeys certPingDnsKeys;

    /**
     * Claims one eligible row and processes it in a single transaction. Called repeatedly
     * by the cron's drain loop.
     *
     * @return {@code true} if a row was claimed (regardless of success/failure of the
     *         per-cert work — the drain loop should keep going); {@code false} when no
     *         eligible rows remain.
     */
    @Override
    @Transactional
    public boolean tryProcessOneEligible() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime stuckCutoff = now.minus(AbandonedRenewalCleanup.IN_FLIGHT_HORIZON);

        return renewalScheduleRepository.claimOneEligible(now, stuckCutoff)
                .map(schedule -> {
                    processClaimed(schedule);
                    return true;
                })
                .orElse(false);
    }

    /**
     * Claims one failure whose retry is due and retries it in a single transaction. Called repeatedly by the
     * retry-renewals drain, so a failure comes back at its own time instead of the next daily run.
     *
     * @return {@code true} if a row was claimed; {@code false} when no retry is due
     */
    @Transactional
    public boolean tryProcessOneDueRetry() {
        return renewalScheduleRepository.claimOneDueRetry(OffsetDateTime.now(ZoneOffset.UTC))
                .map(schedule -> {
                    processClaimed(schedule);
                    return true;
                })
                .orElse(false);
    }

    private void processClaimed(RenewalScheduleEntity schedule) {
        // correlationId is set by DrainRunner.runDrain once per cron tick and shared by
        // every cert in this drain. We just read it. Defensive fallback (orphan id) keeps
        // the audit/event records valid if some caller forgot to set it.
        String correlationId = MdcIds.correlationId();
        if (correlationId == null) {
            correlationId = "corr-orphan-" + UUID.randomUUID();
        }

        // Per-cert requestId: the cron-tick requestId (set by ScheduledMdcAspect) is shared
        // across ALL certs in this drain. If two certs in the same drain both published with
        // the same requestId, the agent's two responses would arrive with the same id and the
        // dedup check in CertResponseProcessor.handleRenewalSuccess (keyed by requestId)
        // would suppress the second response as a "duplicate" — silently dropping a real
        // renewal completion. Mint one requestId per cert so each is independently
        // deduplicatable on the response side.
        String parentMdcRequestId = MDC.get("requestId");
        String perCertRequestId = "req-" + UUID.randomUUID();
        MDC.put("requestId", perCertRequestId);

        // CertPing acts: the rows written for this certificate are its own, under this drain's correlation id
        // and the certificate's request id. Each row names the certificate's organization.
        try (AuditScope scope = AuditScope.system(CertificateAuditRecorder.RENEWAL_JOB, null, correlationId)) {
            // A row claimed while IN_PROGRESS lost its previous attempt's result; that attempt's draft is
            // failed in this transaction so the retry below starts from a coherent state.
            if (RenewalStatus.IN_PROGRESS.name().equals(schedule.getLastRenewalStatus())) {
                log.warn("[RenewalTriggerService] Re-claiming stuck schedule for xref={} "
                        + "(IN_PROGRESS since {}). Cleaning up previous attempt before retry.",
                        schedule.getCertificateXref(), schedule.getUpdatedAt());
                OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
                certificateRepository.findByCertificateXref(schedule.getCertificateXref())
                        .ifPresent(source -> abandonedRenewalCleanup.abandon(source, now));
            }

            processOneSchedule(schedule, correlationId);
        } finally {
            // Restore MDC requestId so the NEXT drain iteration starts with the cron-tick id
            // (then immediately overwrites it with its own per-cert id). correlationId is
            // not touched here — DrainRunner.runDrain owns its lifecycle.
            if (parentMdcRequestId != null) {
                MDC.put("requestId", parentMdcRequestId);
            } else {
                MDC.remove("requestId");
            }
        }
    }

    /**
     * Per-cert processing. Catches exceptions internally and writes "I tried and failed"
     * state markers (schedule=FAILED, draft=RENEWAL_FAILED, audit event) so the
     * surrounding tx still commits with a definite outcome — preventing the row from
     * being repeatedly re-claimed in a tight loop when the failure is deterministic.
     */
    private void processOneSchedule(RenewalScheduleEntity schedule, String correlationId) {
        String certXref = schedule.getCertificateXref();
        CertificateEntity renewedDraft = null;
        String requestId = null;
        boolean movedToRenewing = false;
        boolean publishing = false;

        CertificateEntity cert = certificateRepository.findByCertificateXref(certXref).orElse(null);
        if (cert == null) {
            log.warn("[RenewalTriggerService] Cert not found for xref={} — marking schedule FAILED", certXref);
            parkFailedSchedule(schedule);
            return;
        }

        Long organizationId = cert.getOrganizationId();

        // Read past the cache: a super admin's switch-off holds the renewals at once, before the
        // feature lifecycle has disabled the schedules.
        Optional<String> stoppedBy = organizationId == null ? Optional.empty()
                : featureFlagResolver.automaticWorkBlockerUncached(FeatureFlags.CERTIFICATE_RENEWAL, organizationId);
        if (stoppedBy.isPresent()) {
            holdForFeature(schedule, cert, stoppedBy.get());
            return;
        }
        Optional<Instant> expiredKey = organizationId == null ? Optional.empty()
                : expiredDnsKey(schedule, cert, organizationId);
        if (expiredKey.isPresent()) {
            holdForExpiredDnsKey(schedule, cert, expiredKey.get());
            return;
        }

        // Skip if the CA used for this cert is disabled for this org via feature flag.
        String caFeatureKey = cert.getCaProvider() != null ? toCaFeatureKey(cert.getCaProvider().name()) : null;
        if (caFeatureKey != null && !featureFlagService.isEnabled(caFeatureKey, organizationId)) {
            log.info("[RenewalTriggerService] CA '{}' disabled for org={}; xref={} — marking schedule FAILED",
                    cert.getCaProvider(), organizationId, certXref);
            scheduleFailedRetry(schedule);
            certificateAudit.autoRenewalSkippedByJob(cert, caFeatureKey);
            return;
        }

        // Skip if certificate is not in a renewable state.
        if (!certificateStatusValidator.isEligibleForScheduledRenewal(cert, certXref)) {
            // RENEWING means another attempt is still in flight (e.g. an agent-side
            // scheduled retry from a prior rate-limit). Don't mark the schedule FAILED
            // permanently — the prior attempt should complete and move the cert out of
            // RENEWING, after which this row should be re-checked. Just leave the
            // schedule untouched so the next cron tick re-evaluates eligibility.
            boolean stillRenewing = "RENEWING".equals(cert.getStatus());
            log.info("[RenewalTriggerService] Cert status='{}' not eligible for scheduled renewal: xref={} ({})",
                    cert.getStatus(), certXref, stillRenewing ? "leaving schedule unchanged — retry in flight" : "marking FAILED");
            if (!stillRenewing) {
                scheduleFailedRetry(schedule);
            }
            return;
        }

        // AKAMAI_CPS special certs: re-issue via CertIssuanceCommand because Akamai holds
        // the private key — a normal CertRenewalCommand would generate a mismatched key pair.
        // The original cert stays ACTIVE until the new special cert is issued and deployed.
        if (AkamaiSpecialIssuanceService.AKAMAI_CPS.equals(cert.getSpecialCertificateType())) {
            processAkamaiSpecial(schedule, cert, organizationId);
            return;
        }

        String previousStatus = cert.getStatus();
        try {
            // 1. Build and persist the renewed draft.
            String renewedXref = com.certmanagement.service.cert.CertificateXrefs.newXref();
            String renewedCertSecretHandle = renewalDraftHelper.deriveRenewedCertSecretHandle(
                    schedule.getCertSecretHandle(), cert.getCertSecretHandle(), renewedXref);
            renewedDraft = renewalDraftHelper.buildRenewedDraft(cert, renewedXref, renewedCertSecretHandle);
            certificateRepository.save(renewedDraft);

            // 2. Mark the schedule IN_PROGRESS (state marker — keeps this row out of the
            //    next claim query until SUCCESS/FAILED or until the stuck-timeout expires).
            schedule.setLastRenewalStatus(RenewalStatus.IN_PROGRESS.name());
            renewalScheduleRepository.save(schedule);

            // 3. Move the source cert to RENEWING.
            certificateRepository.updateStatus(certXref, CertificateStatus.RENEWING.name());
            movedToRenewing = true;

            // 4. Audit event.
            requestId = MdcIds.requestId();
            CertificateEventEntity event = CertificateEventEntity.builder()
                    .certificateXref(certXref)
                    .organizationId(organizationId)
                    .eventType(CertEventType.RENEWAL_REQUESTED.name())
                    .fromStatus(previousStatus)
                    .toStatus(CertificateStatus.RENEWING.name())
                    .requestId(requestId)
                    .correlationId(correlationId)
                    .source(EventSource.SCHEDULER.value())
                    .userId(null)
                    .details("{\"renewedCertificateXref\":\"" + renewedXref + "\"}")
                    .build();
            certEventRepository.save(event);
            certificateAudit.autoRenewalStarted(cert, null);

            // 5. Resolve domain context and DNS credentials.
            DomainCredentialConfigEntity credConfig = domainCredConfigRepository
                    .findById(schedule.getDomainCredentialConfigId())
                    .orElseThrow(() -> new IllegalStateException(
                            "DomainCredentialConfig not found for schedule xref=" + certXref
                                    + " configId=" + schedule.getDomainCredentialConfigId()));

            UserDomainCertEntity udc = udcRepository.findById(cert.getUserDomainCertId())
                    .orElseThrow(() -> new IllegalStateException(
                            "UserDomainCert not found for cert xref=" + certXref
                                    + " udcId=" + cert.getUserDomainCertId()));
            String primaryDomain = udc.getDomain();
            Map<String, String> dnsConfig = credConfig.getDnsConfig();
            String primaryCredXref = SanDomainHelper.lookupRootCredXref(dnsConfig, primaryDomain);
            if (primaryCredXref == null) {
                throw new MissingDnsCredentialConfigurationException(
                        "No DNS credential configured for primary domain '" + primaryDomain
                                + "' in credential config for xref=" + certXref);
            }
            CredentialReferenceEntity primaryDnsCred = resolveActiveCredential(organizationId, primaryCredXref);

            List<CertRenewalCommand.SanDomainEntry> sanEntries = renewalDraftHelper
                    .buildRenewalSanEntriesFromConfig(
                            primaryDomain,
                            cert.getSanDomains(),
                            dnsConfig,
                            primaryDnsCred,
                            xref -> resolveActiveCredential(organizationId, xref));

            // 6. Build and publish the CERT_RENEWAL command.
            CertRenewalCommand command = renewalDraftHelper.buildRenewalCommand(
                    cert, renewedDraft, schedule, primaryDomain, organizationId,
                    orgTypeResolver.resolve(organizationId),
                    requestId, correlationId, primaryDnsCred, sanEntries);
            publishing = true;
            publisher.publishRenewal(command);

            log.info("[RenewalTriggerService] Triggered renewal: xref={}, domain={}, organizationId={}",
                    certXref, cert.getDomain(), organizationId);

        } catch (Exception e) {
            if (publishing && PublishOutcome.of(e) == PublishOutcome.UNKNOWN) {
                // The command may be on its way to the agent: a second attempt would race it at the CA. The attempt
                // stays in flight, and ends with its result or with the stalled-renewal recovery.
                log.error("[RENEWAL_PUBLISH_UNKNOWN] xref={} draft={}: the CERT_RENEWAL may have been sent; "
                        + "the attempt stays in flight: {}", certXref, renewedDraft.getCertificateXref(), e.getMessage());
                return;
            }
            log.error("[RenewalTriggerService] Failed to trigger renewal for xref={}: {}",
                    certXref, e.getMessage(), e);
            // Write failure state in this same tx so the row commits with a definite
            // outcome (FAILED), not the partial IN_PROGRESS state. Without this, the
            // tx would still commit but with IN_PROGRESS — and a deterministic failure
            // would be re-claimed on every drain loop iteration after the stuck-timeout
            // expires.
            try {
                if (e instanceof MissingDnsCredentialConfigurationException) {
                    parkFailedSchedule(schedule);
                } else {
                    scheduleFailedRetry(schedule);
                }
                certificateRepository.updateStatus(certXref, previousStatus);
                if (renewedDraft != null) {
                    renewedDraft.setStatus(CertificateStatus.RENEWAL_FAILED.name());
                    renewedDraft.setLastErrorCode("RENEWAL_TRIGGER_FAILED");
                    renewedDraft.setLastErrorMessage(e.getMessage());
                    renewedDraft.setLastErrorAt(OffsetDateTime.now(ZoneOffset.UTC));
                    certificateRepository.save(renewedDraft);
                }

                CertificateEventEntity failureEvent = CertificateEventEntity.builder()
                        .certificateXref(certXref)
                        .organizationId(organizationId)
                        .eventType(CertEventType.RENEWAL_PUBLISH_FAILED.name())
                        .fromStatus(movedToRenewing ? CertificateStatus.RENEWING.name() : previousStatus)
                        .toStatus(previousStatus)
                        .requestId(requestId)
                        .correlationId(correlationId)
                        .source(EventSource.SCHEDULER.value())
                        .userId(null)
                        .details("{\"errorCode\":\"RENEWAL_TRIGGER_FAILED\",\"errorDetail\":\""
                                + (e.getMessage() != null ? e.getMessage().replace("\"", "\\\"") : "")
                                + "\",\"renewedCertificateXref\":\""
                                + (renewedDraft != null ? renewedDraft.getCertificateXref() : "")
                                + "\"}")
                        .build();
                certEventRepository.save(failureEvent);
                certificateAudit.renewalFailed(cert, triggerFailureReason(e), null);
            } catch (Exception revertEx) {
                log.error("[RenewalTriggerService] Failed to revert status for xref={}: {}",
                        certXref, revertEx.getMessage());
            }
        }
    }

    /**
     * Akamai-special variant: triggers a re-issuance (not a renewal command) because
     * Akamai owns the private key.
     */
    private void processAkamaiSpecial(RenewalScheduleEntity schedule,
                                      CertificateEntity cert,
                                      Long organizationId) {
        String certXref = schedule.getCertificateXref();
        try {
            schedule.setLastRenewalStatus(RenewalStatus.IN_PROGRESS.name());
            renewalScheduleRepository.save(schedule);

            DomainCredentialConfigEntity credConfig = domainCredConfigRepository
                    .findById(schedule.getDomainCredentialConfigId())
                    .orElseThrow(() -> new IllegalStateException(
                            "DomainCredentialConfig not found for Akamai-special renewal xref=" + certXref
                                    + " configId=" + schedule.getDomainCredentialConfigId()));

            CredentialReferenceEntity akamaiCred = resolveAkamaiCred(credConfig, organizationId);

            akamaiSpecialIssuanceService.triggerAkamaiSpecialIssuance(
                    organizationId, cert, schedule, credConfig, akamaiCred);

            certificateAudit.autoRenewalStarted(cert, AkamaiSpecialIssuanceService.AKAMAI_CPS);
            log.info("[RenewalTriggerService] Triggered Akamai-special renewal: xref={}, domain={}, org={}",
                    certXref, cert.getDomain(), organizationId);
        } catch (Exception e) {
            log.error("[RenewalTriggerService] Failed to trigger Akamai-special renewal for xref={}: {}",
                    certXref, e.getMessage(), e);
            try {
                scheduleFailedRetry(schedule);
                certificateAudit.renewalFailed(cert, triggerFailureReason(e), null);
            } catch (Exception revertEx) {
                log.error("[RenewalTriggerService] Failed to mark schedule FAILED for Akamai xref={}: {}",
                        certXref, revertEx.getMessage());
            }
        }
    }

    /**
     * Mirrors {@code CertIssuanceService.resolveActiveCredential}: fetch by xref and
     * reject if not ACTIVE. Surfaces a deactivated DNS credential before we publish a
     * CERT_RENEWAL the agent cannot fulfil.
     */
    private CredentialReferenceEntity resolveActiveCredential(Long organizationId, String credXref) {
        CredentialReferenceEntity cred = credentialService.getByXref(organizationId, credXref);
        if (!"ACTIVE".equals(cred.getStatus())) {
            throw new IllegalStateException(
                    "credentialXref '" + credXref + "' is not ACTIVE for organization " + organizationId);
        }
        return cred;
    }

    private CredentialReferenceEntity resolveAkamaiCred(DomainCredentialConfigEntity credConfig,
                                                        Long organizationId) {
        if (credConfig.getDeploymentTargets() == null || credConfig.getDeploymentTargets().isEmpty()) {
            throw new IllegalStateException(
                    "No deployment targets in credConfig id=" + credConfig.getId()
                            + " — cannot resolve AKAMAI_CPS credential for renewal");
        }
        for (String credXref : credConfig.getDeploymentTargets()) {
            CredentialReferenceEntity cred = credentialService.getByXref(organizationId, credXref);
            if (AkamaiSpecialIssuanceService.AKAMAI_CPS.equals(cred.getProvider())) {
                return cred;
            }
        }
        throw new IllegalStateException(
                "No AKAMAI_CPS credential found in deployment targets for credConfig id=" + credConfig.getId());
    }

    private static String toCaFeatureKey(String caProvider) {
        if (caProvider == null) return null;
        return switch (caProvider.toUpperCase()) {
            case "LETS_ENCRYPT" -> FeatureFlags.CA_LETS_ENCRYPT;
            case "DIGICERT"      -> FeatureFlags.CA_DIGICERT;
            case "GLOBALSIGN"    -> FeatureFlags.CA_GLOBALSIGN;
            default              -> null;
        };
    }

    /**
     * The reason a failed trigger is recorded with, by the failure's type only (never its message): a DNS credential
     * missing from the configuration, or the trigger failing otherwise.
     */
    static AuditReason triggerFailureReason(Exception failure) {
        if (failure instanceof MissingDnsCredentialConfigurationException
                || failure instanceof ResourceNotFoundException) {
            return AuditReason.of("DNS_CREDENTIAL_MISSING");
        }
        return AuditReason.of("RENEWAL_TRIGGER_FAILED");
    }

    /** Holds the schedule while {@code featureKey} is off; the claim checks it again when it comes due. */
    private void holdForFeature(RenewalScheduleEntity schedule, CertificateEntity cert, String featureKey) {
        log.info("[RenewalTriggerService] {} off for org={}; xref={} — holding schedule", featureKey,
                cert.getOrganizationId(), schedule.getCertificateXref());
        schedule.setLastRenewalStatus(RenewalStatus.FEATURE_HOLD.name());
        schedule.setNextAttemptAt(RenewalRetryPolicy.holdRecheckAt());
        renewalScheduleRepository.save(schedule);
        certificateAudit.autoRenewalSkippedByJob(cert, featureKey);
    }

    /** The earliest expiry of an expired CertPing DNS key the schedule's renewal would publish through. */
    private Optional<Instant> expiredDnsKey(RenewalScheduleEntity schedule, CertificateEntity cert,
                                            long organizationId) {
        Optional<Map<String, String>> dnsConfig = domainCredConfigRepository
                .findById(schedule.getDomainCredentialConfigId())
                .map(DomainCredentialConfigEntity::getDnsConfig);
        Optional<String> primaryDomain = udcRepository.findById(cert.getUserDomainCertId())
                .map(UserDomainCertEntity::getDomain);
        if (dnsConfig.isEmpty() || primaryDomain.isEmpty()) {
            return Optional.empty();
        }
        return certPingDnsKeys.earliestExpired(organizationId, renewalDraftHelper.renewalDnsCredentialXrefs(
                primaryDomain.get(), cert.getSanDomains(), dnsConfig.get()), Instant.now());
    }

    /**
     * Holds the schedule while a CertPing DNS key it renews through has expired: a renewal would only fail at
     * the DNS API. Checked again every {@link #DNS_KEY_HOLD_RECHECK}, and rearmed at once when the key is
     * renewed; audited once, when the hold starts.
     */
    private void holdForExpiredDnsKey(RenewalScheduleEntity schedule, CertificateEntity cert, Instant expiredAt) {
        boolean starts = !RenewalStatus.DNS_KEY_EXPIRED_HOLD.name().equals(schedule.getLastRenewalStatus());
        log.info("[RenewalTriggerService] CertPing DNS key expired at {} for org={}; xref={} — holding schedule",
                expiredAt, cert.getOrganizationId(), schedule.getCertificateXref());
        schedule.setLastRenewalStatus(RenewalStatus.DNS_KEY_EXPIRED_HOLD.name());
        schedule.setNextAttemptAt(OffsetDateTime.now(ZoneOffset.UTC).plus(DNS_KEY_HOLD_RECHECK));
        renewalScheduleRepository.save(schedule);
        if (starts) {
            certificateAudit.autoRenewalHeldByExpiredDnsKey(cert, expiredAt);
        }
    }

    private void parkFailedSchedule(RenewalScheduleEntity schedule) {
        schedule.setLastRenewalStatus(RenewalStatus.FAILED.name());
        schedule.setNextAttemptAt(null);
        renewalScheduleRepository.save(schedule);
    }

    private void scheduleFailedRetry(RenewalScheduleEntity schedule) {
        RenewalRetryPolicy.recordFailure(schedule);
        renewalScheduleRepository.save(schedule);
    }
}
