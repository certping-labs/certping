// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.ErrorCodes;
import com.certmanagement.dto.cert.RevokeRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.enums.EventSource;
import com.certmanagement.enums.RenewalStatus;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.audit.AuditReasons;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cbom.CertificateInventoryChangedEvent;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Package-private transactional helper for {@link CertIssuanceService}.
 *
 * <p>Each public method runs in its own {@code @Transactional} boundary, which lets
 * {@code CertIssuanceService} commit the DB record <em>before</em> publishing to the queue.
 * This prevents the dual-write problem where:
 * <ul>
 *   <li>queue publish succeeds but the DB commit later fails (orphaned agent message), or</li>
 *   <li>queue publish fails but the cert is left stuck in PENDING (no agent will ever respond).</li>
 * </ul>
 *
 * <p>If the queue publish fails after {@code persistIssuance} commits, a second call to
 * {@code markIssuancePublishFailed} updates the cert to FAILED in a fresh transaction.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class CertPersistenceService {

    static final class RenewalPersistResult {
        private final CertificateEntity previousCert;
        private final CertificateEntity renewedCert;

        RenewalPersistResult(CertificateEntity previousCert, CertificateEntity renewedCert) {
            this.previousCert = previousCert;
            this.renewedCert = renewedCert;
        }

        CertificateEntity getPreviousCert() {
            return previousCert;
        }

        CertificateEntity getRenewedCert() {
            return renewedCert;
        }
    }

    private final CertificateRepository            certificateRepository;
    private final CertificateEventRepository       eventRepository;
    private final RenewalScheduleRepository        renewalScheduleRepository;
    private final DeploymentRepository             deploymentRepository;
    private final DomainCredentialConfigRepository domainCredConfigRepository;
    private final CertManualIssuanceStateRepository certManualIssuanceStateRepository;
    private final ObjectMapper                     objectMapper;
    private final OrgTypeResolver orgTypeResolver;
    private final ApplicationEventPublisher eventPublisher;
    private final CertificateFeatureLocks certificateFeatureLocks;
    /** Writes each change's audit row in the change's own transaction. */
    private final CertificateAuditRecorder certificateAudit;

    /** The 423 an issuance with deployment targets gets while CERTIFICATE_DEPLOYMENT is off. */
    static final String DEPLOYMENT_OFF_MESSAGE = "Automatic deployment is turned off for your organization. "
            + "Issue the certificate without deployment targets, or ask an admin to turn deployment back on.";

    /** Optional: absent in unit tests that build this service without it. */
    @Autowired(required = false)
    private CertAgentPublisher certAgentPublisher;

    // ------------------------------------------------------------------ //
    //  Issuance
    // ------------------------------------------------------------------ //

    /**
     * Atomically saves:
     *   1. DomainCredentialConfigEntity  (first — schedule FK references it)
     *   2. CertificateEntity             (status=PENDING)
     *   3. RenewalScheduleEntity         (FK set after credConfig is saved)
     *   4. ISSUANCE_REQUESTED audit event
     *
     * All in one transaction committed before the caller publishes to the queue.
     */
    @Transactional
    CertificateEntity persistIssuance(CertificateEntity cert,
                                      DomainCredentialConfigEntity credConfig,
                                      RenewalScheduleEntity schedule,
                                      String requestId,
                                      String correlationId) {
        lockIssuanceFeatures(cert, credConfig);
        // Upsert live config by user_domain_cert_id: replace dns_config and deployment_targets if it already exists.
        List<String> targetsBefore = new ArrayList<>();
        DomainCredentialConfigEntity savedConfig = domainCredConfigRepository
                .findByUserDomainCertId(credConfig.getUserDomainCertId())
                .map(existing -> {
                    if (existing.getDeploymentTargets() != null) {
                        targetsBefore.addAll(existing.getDeploymentTargets());
                    }
                    existing.setDnsConfig(new LinkedHashMap<>(credConfig.getDnsConfig()));
                    existing.setDeploymentTargets(new ArrayList<>(credConfig.getDeploymentTargets()));
                    return domainCredConfigRepository.save(existing);
                })
                .orElseGet(() -> domainCredConfigRepository.save(credConfig));
        schedule.setDomainCredentialConfigId(savedConfig.getId());

        certificateRepository.save(cert);
        renewalScheduleRepository.save(schedule);

        insertEvent(cert.getCertificateXref(), cert.getOrganizationId(),
            CertEventType.ISSUANCE_REQUESTED.name(), null, CertificateStatus.PENDING.name(),
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
                Map.of("domain", orEmpty(cert.getDomain()), "caProvider", cert.getCaProvider()));
        certificateAudit.issueRequested(cert, credConfig.getDeploymentTargets() == null ? 0
                : credConfig.getDeploymentTargets().size());
        // The request's deployment targets replace the domain's: each one added or dropped is its own row.
        certificateAudit.deploymentTargetsReplaced(cert.getOrganizationId(), cert.getDomain(), targetsBefore,
                credConfig.getDeploymentTargets());
        return cert;
    }

    /**
     * Serializes with an org admin switching issuance, renewal, the CA or deployment off (clear-first),
     * then re-checks past the cache the flags a new issuance needs.
     *
     * <p>{@code CERTIFICATE_RENEWAL} is locked but not required: the schedule saved here stays disabled
     * until the issuance succeeds, and the success handler re-checks renewal under this same lock and
     * leaves the schedule off (with an AUTO_RENEW_SKIPPED_FEATURE_OFF event) while it is off.
     *
     * @throws com.certmanagement.exception.FeatureDisabledException when issuance, the CA, or (with
     *         targets) deployment is off
     */
    private void lockIssuanceFeatures(CertificateEntity cert, DomainCredentialConfigEntity credConfig) {
        certificateFeatureLocks.lockAndRequire(cert.getOrganizationId(), requiredIssuanceFeatureKeys(cert, credConfig),
                List.of(FeatureFlags.CERTIFICATE_RENEWAL), DEPLOYMENT_OFF_MESSAGE);
    }

    /** The features a new issuance needs on: issuance, its CA, and deployment when it has targets. */
    private static List<String> requiredIssuanceFeatureKeys(CertificateEntity cert,
                                                            DomainCredentialConfigEntity credConfig) {
        List<String> featureKeys = new ArrayList<>(List.of(FeatureFlags.CERTIFICATE_ISSUANCE));
        if (cert.getCaProvider() != null) {
            featureKeys.add(CertIssuanceService.toCaFeatureKey(cert.getCaProvider()));
        }
        if (credConfig.getDeploymentTargets() != null && !credConfig.getDeploymentTargets().isEmpty()) {
            featureKeys.add(FeatureFlags.CERTIFICATE_DEPLOYMENT);
        }
        return featureKeys;
    }

    /**
     * Marks a PENDING cert as FAILED because the queue publish step failed after DB commit.
     */
    @Transactional
    void markIssuancePublishFailed(String certXref, Long organizationId,
                                   String requestId, String correlationId,
                                   String errorDetail) {
        certificateRepository.findByCertificateXrefAndOrganizationId(certXref, organizationId).ifPresent(c -> {
            c.setStatus(CertificateStatus.FAILED.name());
            c.setLastErrorCode(ErrorCodes.QUEUE_PUBLISH_FAILED);
            c.setLastErrorMessage(errorDetail);
            c.setLastErrorAt(OffsetDateTime.now(ZoneOffset.UTC));
            certificateRepository.save(c);
            // The member's request was accepted (issue_requested); it then could not reach the agent.
            certificateAudit.issueFailed(c, AuditReasons.SERVICE_UNAVAILABLE, null);
        });
        insertEvent(certXref, organizationId,
                CertEventType.ISSUANCE_PUBLISH_FAILED.name(), CertificateStatus.PENDING.name(), CertificateStatus.FAILED.name(),
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
                Map.of("errorCode", ErrorCodes.QUEUE_PUBLISH_FAILED,
                       "errorDetail", errorDetail != null ? errorDetail : ""));
    }

    // ------------------------------------------------------------------ //
    //  Renewal
    // ------------------------------------------------------------------ //

    /**
     * Replaces the deployment targets of {@code cert}'s domain with the ones a renewal request named, with a
     * {@code deployment_target.*} row per target that changed.
     */
    private void replaceDeploymentTargets(DomainCredentialConfigEntity credConfig, List<String> targets,
                                          CertificateEntity cert) {
        List<String> before = credConfig.getDeploymentTargets() == null ? List.of()
                : new ArrayList<>(credConfig.getDeploymentTargets());
        credConfig.setDeploymentTargets(new ArrayList<>(targets));
        domainCredConfigRepository.save(credConfig);
        certificateAudit.deploymentTargetsReplaced(cert.getOrganizationId(), cert.getDomain(), before, targets);
    }

    /**
     * Sets cert to RENEWING, replaces the domain's deployment targets when the request named some, marks renewal
     * schedule IN_PROGRESS, and inserts a RENEWAL_REQUESTED audit event — all in one transaction, so a refused
     * renewal changes nothing.
     *
     * @param replacementTargets the deployment targets the request named, or {@code null} to keep the domain's
     * @throws DuplicateResourceException when the certificate is no longer in a status a renewal may start from,
     *         such as a renewal the scheduler started meanwhile
     */
    @Transactional
    RenewalPersistResult persistRenewal(CertificateEntity previousCert,
                                        CertificateEntity renewedCert,
                                        DomainCredentialConfigEntity credConfig,
                                        List<String> replacementTargets,
                                        String prevStatus,
                                        String requestId,
                                        String correlationId) {
        int moved = certificateRepository.tryMarkRenewing(previousCert.getCertificateXref(),
                previousCert.getOrganizationId(), OffsetDateTime.now(ZoneOffset.UTC));
        if (moved == 0) {
            throw new DuplicateResourceException(
                    "Certificate '" + previousCert.getCertificateXref() + "' already has a renewal in progress.");
        }
        if (replacementTargets != null) {
            replaceDeploymentTargets(credConfig, replacementTargets, previousCert);
        }
        previousCert.setStatus(CertificateStatus.RENEWING.name());
        CertificateEntity savedPrevious = previousCert;
        CertificateEntity savedRenewed = certificateRepository.save(renewedCert);
        String savedRenewedXref = savedRenewed != null
            ? savedRenewed.getCertificateXref()
            : (renewedCert != null ? renewedCert.getCertificateXref() : null);

        renewalScheduleRepository
                .findByCertificateXref(previousCert.getCertificateXref())
                .ifPresent(rs -> {
                    if (!rs.heldByFeatureSwitch()) {
                        rs.setLastRenewalStatus(RenewalStatus.IN_PROGRESS.name());
                    }
                    renewalScheduleRepository.save(rs);
                });

        insertEvent(previousCert.getCertificateXref(), previousCert.getOrganizationId(),
            CertEventType.RENEWAL_REQUESTED.name(), prevStatus, CertificateStatus.RENEWING.name(),
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
                Map.of("triggeredBy", "manual",
                       "renewedCertificateXref", orEmpty(savedRenewedXref)));
        certificateAudit.renewalRequested(previousCert);
        return new RenewalPersistResult(savedPrevious, savedRenewed != null ? savedRenewed : renewedCert);
    }

    /**
     * Reverts cert to {@code prevStatus} because the queue publish for renewal failed.
     * Marks renewal schedule as FAILED.
     */
    @Transactional
    void markRenewalPublishFailed(String previousCertXref,
                                  String renewedCertXref,
                                  Long organizationId,
                                  String prevStatus,
                                  String requestId, String correlationId,
                                  String errorDetail) {
        certificateRepository.findByCertificateXrefAndOrganizationId(previousCertXref, organizationId).ifPresent(c -> {
            c.setStatus(prevStatus);
            c.setLastErrorCode(ErrorCodes.QUEUE_PUBLISH_FAILED);
            c.setLastErrorMessage(errorDetail);
            c.setLastErrorAt(OffsetDateTime.now(ZoneOffset.UTC));
            certificateRepository.save(c);
            certificateAudit.renewalFailed(c, AuditReasons.SERVICE_UNAVAILABLE, null);
        });
        if (renewedCertXref != null && !renewedCertXref.isBlank()) {
            certificateRepository.findByCertificateXrefAndOrganizationId(renewedCertXref, organizationId)
                    .ifPresent(c -> {
                        c.setStatus(CertificateStatus.RENEWAL_FAILED.name());
                        c.setLastErrorCode(ErrorCodes.QUEUE_PUBLISH_FAILED);
                        c.setLastErrorMessage(errorDetail);
                        c.setLastErrorAt(OffsetDateTime.now(ZoneOffset.UTC));
                        certificateRepository.save(c);
                    });
        }
        renewalScheduleRepository
                .findByCertificateXref(previousCertXref)
                .ifPresent(rs -> {
                    RenewalRetryPolicy.recordFailure(rs);
                    renewalScheduleRepository.save(rs);
                });
        insertEvent(previousCertXref, organizationId,
            CertEventType.RENEWAL_PUBLISH_FAILED.name(), CertificateStatus.RENEWING.name(), prevStatus,
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
                Map.of("errorCode", ErrorCodes.QUEUE_PUBLISH_FAILED,
                       "errorDetail", errorDetail != null ? errorDetail : "",
                       "renewedCertificateXref", orEmpty(renewedCertXref)));
    }

    // ------------------------------------------------------------------ //
    //  Deployment
    // ------------------------------------------------------------------ //

    /**
     * Inserts a DEPLOYMENT_REQUESTED audit event.
     * Certificate status is intentionally left unchanged; deployment state is tracked separately.
     */
    @Transactional
    CertificateEntity persistDeployment(CertificateEntity cert,
                                        String prevStatus,
                                        String requestId,
                                        String correlationId,
                                        String targetType,
                                        String certificateName) {
        insertEvent(cert.getCertificateXref(), cert.getOrganizationId(),
            CertEventType.DEPLOYMENT_REQUESTED.name(), prevStatus, prevStatus,
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
                Map.of("targetType", targetType,
                       "certificateName", certificateName != null ? certificateName : ""));
        certificateAudit.deploymentRequested(cert, targetType);
        return cert;
    }

    /**
     * Reverts cert to {@code prevStatus} because the queue publish for deployment failed.
     */
    @Transactional
    void markDeploymentPublishFailed(String certXref, Long organizationId,
                                     String prevStatus,
                                     String requestId, String correlationId,
                                     String errorDetail) {
        certificateRepository.findByCertificateXrefAndOrganizationId(certXref, organizationId).ifPresent(c -> {
            c.setStatus(prevStatus);
            c.setLastErrorCode(ErrorCodes.QUEUE_PUBLISH_FAILED);
            c.setLastErrorMessage(errorDetail);
            c.setLastErrorAt(OffsetDateTime.now(ZoneOffset.UTC));
            certificateRepository.save(c);
        });
        insertEvent(certXref, organizationId,
            CertEventType.DEPLOYMENT_PUBLISH_FAILED.name(), prevStatus, prevStatus,
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
                Map.of("errorCode", ErrorCodes.QUEUE_PUBLISH_FAILED,
                       "errorDetail", errorDetail != null ? errorDetail : ""));
    }

    // ------------------------------------------------------------------ //
    //  Delete (soft)
    // ------------------------------------------------------------------ //

    /**
     * Soft-deletes a certificate, cascades to related entities, and inserts a
     * CERT_DELETED audit event.
     *
     * @return number of rows updated by soft-delete (0 when already deleted/not found)
     */
    @Transactional
    int softDeleteAndInsertEvent(String certificateXref,
                                 Long organizationId,
                                 String previousStatus,
                                 String requestId,
                                 String correlationId) {
        return softDeleteAndInsertEvent(certificateXref, organizationId, previousStatus, requestId, correlationId,
                null);
    }

    /**
     * {@link #softDeleteAndInsertEvent(String, Long, String, String, String)}, recording what removed the
     * certificate when it was not its own delete.
     *
     * @param deleteSource {@code MANAGED_DOMAIN} or {@code EXPIRY_CLEANUP}; null for the certificate's own delete
     */
    @Transactional
    int softDeleteAndInsertEvent(String certificateXref,
                                 Long organizationId,
                                 String previousStatus,
                                 String requestId,
                                 String correlationId,
                                 String deleteSource) {
        // Capture the certificate BEFORE soft-delete — it won't be findable after deleted_at is set
        Optional<CertificateEntity> existing = certificateRepository
                .findByCertificateXrefAndOrganizationId(certificateXref, organizationId);
        String certSecretHandle = existing.map(CertificateEntity::getCertSecretHandle).orElse(null);

        int updated = certificateRepository.softDelete(certificateXref, organizationId);
        if (updated == 0) {
            return 0;
        }

        // Cascade soft-delete to every table that points at this certificate. Every
        // child flips its own is_deleted/deleted_at flag so the @Where(is_deleted=false)
        // filters hide the rows; nothing here issues a hard DELETE. The single legacy
        // exception is cert_manual_issuance_state, which the existing flow already hard-
        // deletes via deleteByCertXref — left as-is to avoid behaviour churn.
        renewalScheduleRepository.softDeleteByXref(certificateXref);
        deploymentRepository.softDeleteByCertificateXrefAndOrganizationId(certificateXref, organizationId);
        certManualIssuanceStateRepository.deleteByCertXref(certificateXref);
        eventRepository.softDeleteByCertificateXref(certificateXref);

        // Publish KV delete command after the transaction commits to avoid dual-write inconsistency
        if (certAgentPublisher != null && certSecretHandle != null && !certSecretHandle.isBlank()) {
            final String handleSnapshot = certSecretHandle;
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    try {
                        certAgentPublisher.publishKvDeleteCommand(
                                certificateXref, handleSnapshot,
                                organizationId.toString(), orgTypeResolver.resolve(organizationId));
                    } catch (Exception e) {
                        log.warn("Failed to publish CERT_SECRET_DELETE_COMMAND for xref={}: {}",
                                certificateXref, e.getMessage());
                    }
                }
            });
        }

        insertEvent(
                certificateXref,
                organizationId,
                CertEventType.CERT_DELETED.name(),
                previousStatus,
                CertificateStatus.DELETED.name(),
                requestId,
                correlationId,
                EventSource.CERT_MANAGER.value(),
                Map.of("reason", "soft_delete"));
        existing.ifPresent(cert -> certificateAudit.deleted(cert, deleteSource, previousStatus));
        eventPublisher.publishEvent(new CertificateInventoryChangedEvent());

        return updated;
    }

    /**
     * Bulk soft-deletes all certificates (and related entities) for an organization.
     * Called during organization deletion. Bypasses per-cert status validation.
     */
    @Transactional
    void softDeleteAllByOrganizationId(Long organizationId) {
        // Collect certs with KV paths before soft-deleting
        List<String[]> kvEntries = new ArrayList<>();
        if (certAgentPublisher != null) {
            try {
                certificateRepository.findActiveWithKvPathByOrganizationId(organizationId)
                        .forEach(cert -> {
                            if (cert.getCertSecretHandle() != null && !cert.getCertSecretHandle().isBlank()) {
                                kvEntries.add(new String[]{cert.getCertificateXref(), cert.getCertSecretHandle()});
                            }
                        });
            } catch (Exception e) {
                log.warn("Failed to find certs with KV paths for org={}: {}", organizationId, e.getMessage());
            }
        }

        certificateRepository.softDeleteAllByOrganizationId(organizationId);
        eventPublisher.publishEvent(new CertificateInventoryChangedEvent());
        renewalScheduleRepository.softDeleteByOrganizationId(organizationId);
        certManualIssuanceStateRepository.softDeleteByOrganizationId(organizationId);

        // Publish KV delete commands after the transaction commits to avoid dual-write inconsistency
        if (!kvEntries.isEmpty()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    for (String[] entry : kvEntries) {
                        try {
                            certAgentPublisher.publishKvDeleteCommand(
                                    entry[0], entry[1],
                                    organizationId.toString(), orgTypeResolver.resolve(organizationId));
                        } catch (Exception e) {
                            log.warn("Failed to publish CERT_SECRET_DELETE_COMMAND for org={}, xref={}: {}",
                                    organizationId, entry[0], e.getMessage());
                        }
                    }
                }
            });
        }

        log.info("Bulk soft-deleted all cert-related entities for organizationId={}", organizationId);
    }

    // ------------------------------------------------------------------ //
    //  Revocation
    // ------------------------------------------------------------------ //

    /**
     * Atomically marks REVOKING (single-row UPDATE), then disables renewal schedule and inserts
     * REVOCATION_REQUESTED. Returns empty if the UPDATE matched no row (concurrent revoke or status
     * changed) — caller must reload and treat REVOKING/REVOKED as idempotent.
     */
    @Transactional
    Optional<CertificateEntity> persistRevocation(String certificateXref,
                                                  Long organizationId,
                                                  String previousStatus,
                                                  RevokeRequest request,
                                                  String requestId,
                                                  String correlationId) {
        String reason = request.getReason();
        if (reason == null || reason.isBlank()) {
            reason = ErrorCodes.DEFAULT_REVOCATION_REASON;
        }
        Integer actorUserId = GatewayRequestContext.getUserId();

        OffsetDateTime updatedAt = OffsetDateTime.now(ZoneOffset.UTC);
        int updated = certificateRepository.tryMarkRevoking(
                certificateXref, organizationId, updatedAt);
        if (updated == 0) {
            return Optional.empty();
        }

        CertificateEntity fresh = certificateRepository
                .findByCertificateXrefAndOrganizationId(certificateXref, organizationId)
                .orElseThrow(() -> new IllegalStateException(
                        "Certificate vanished after tryMarkRevoking: " + certificateXref));

        renewalScheduleRepository
                .findByCertificateXref(certificateXref)
                .ifPresent(rs -> {
                    rs.setEnabled(false);
                    renewalScheduleRepository.save(rs);
                });

        insertEvent(certificateXref, organizationId,
            CertEventType.REVOCATION_REQUESTED.name(), previousStatus, CertificateStatus.REVOKING.name(),
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
            actorUserId, reason,
            Map.of("reason", reason,
                   "userId", actorUserId != null ? actorUserId : ""));

        certificateAudit.revokeRequested(fresh, reason);

        log.info("[persistRevocation] cert={} -> REVOKING, reason={}",
            certificateXref, reason);
        return Optional.of(fresh);
    }

    /**
     * Marks cert REVOCATION_FAILED after queue publish of revocation command fails.
     */
    @Transactional
    void markRevocationPublishFailed(String certXref,
                                     Long organizationId,
                                     String requestId,
                                     String correlationId,
                                     String errorDetail) {
        certificateRepository.findByCertificateXrefAndOrganizationId(certXref, organizationId).ifPresent(cert -> {
            if (!CertificateStatus.REVOKING.name().equals(cert.getStatus())) {
                log.warn("[markRevocationPublishFailed] cert={} expected REVOKING but was {} — skipping",
                        certXref, cert.getStatus());
                return;
            }
            cert.setStatus(CertificateStatus.REVOCATION_FAILED.name());
            cert.setLastErrorCode(ErrorCodes.REVOCATION_PUBLISH_FAILED);
            cert.setLastErrorMessage(errorDetail);
            cert.setLastErrorAt(OffsetDateTime.now(ZoneOffset.UTC));
            cert.setUpdatedAt(OffsetDateTime.now(ZoneOffset.UTC));
            certificateRepository.save(cert);

            insertEvent(certXref, organizationId,
                    CertEventType.REVOCATION_FAILED.name(), CertificateStatus.REVOKING.name(), CertificateStatus.REVOCATION_FAILED.name(),
                    requestId, correlationId, EventSource.CERT_MANAGER.value(),
                    Map.of("errorCode", ErrorCodes.REVOCATION_PUBLISH_FAILED,
                           "errorDetail", orEmpty(errorDetail)));
            certificateAudit.revocationFailed(cert, AuditReasons.SERVICE_UNAVAILABLE, null);

            log.warn("[markRevocationPublishFailed] cert={} → REVOCATION_FAILED, reason={}",
                    certXref, errorDetail);
        });
    }

    // ------------------------------------------------------------------ //
    //  Private helpers
    // ------------------------------------------------------------------ //

    private static String orEmpty(String value) {
        return value != null ? value : "";
    }

    private void insertEvent(String xref, Long organizationId, String eventType,
                             String fromStatus, String toStatus,
                             String requestId, String correlationId,
                             String source, Map<String, Object> details) {
        insertEvent(xref, organizationId, eventType, fromStatus, toStatus,
            requestId, correlationId, source,
            GatewayRequestContext.getUserId(), null, details);
    }

    private void insertEvent(String xref, Long organizationId, String eventType,
                 String fromStatus, String toStatus,
                 String requestId, String correlationId,
                 String source, Integer userId, String reason,
                 Map<String, Object> details) {
        try {
            CertificateEventEntity event = CertificateEventEntity.builder()
                    .certificateXref(xref)
                    .organizationId(organizationId)
                    .eventType(eventType)
                    .fromStatus(fromStatus)
                    .toStatus(toStatus)
                    .requestId(requestId)
                    .correlationId(correlationId)
                    .userId(userId)
                    .reason(reason)
                    .source(source)
                    .details(objectMapper.writeValueAsString(details))
                    .build();
            eventRepository.save(event);
        } catch (Exception e) {
            log.error("Failed to insert {} event for xref={}: {}", eventType, xref, e.getMessage(), e);
        }
    }
}
