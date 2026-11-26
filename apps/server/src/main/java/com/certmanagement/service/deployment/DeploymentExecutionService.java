// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditReasons;
import com.certmanagement.constants.ErrorCodes;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DeploymentEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertDeploymentCommand;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.cert.AkamaiSpecialIssuanceService;
import com.certmanagement.service.cert.CredentialReferenceService;
import com.certmanagement.service.deployment.config.DeploymentConfigEnvelope;
import com.certmanagement.util.MdcIds;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Single home for all certificate deployment dispatch logic.
 *
 * <p>
 * Two callers, two behaviours:
 * <ul>
 * <li>{@link #dispatchSingle} — manual deploy endpoint. Caller has already
 * validated
 * preconditions; this method throws on any failure.</li>
 * <li>{@link #dispatchAll} — automatic post-issuance / post-renewal. Each
 * target is
 * attempted independently; failures are logged and skipped so remaining targets
 * are always attempted.</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeploymentExecutionService {

    private static final Set<String> TARGETS_REQUIRED_PROVIDERS = Set.of(
            "AWS_ALB", "AWS_NLB",
            "AWS_API_GW_REST", "AWS_API_GW_HTTP",
            "AZURE_APP_GW", "AZURE_APP_GW_CONTAINERS",
            "AZURE_AFD");

    private final CredentialReferenceService credentialService;
    private final CertAgentPublisher publisher;
    private final DeploymentTrackingService trackingService;
    private final UserDomainCertRepository udcRepository;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final DomainCredentialConfigRepository domainCredConfigRepository;
    private final CertDeploymentConfigService certDeploymentConfigService;
    private final CertificateRepository certificateRepository;
    private final AkamaiSpecialIssuanceService akamaiSpecialIssuanceService;
    private final ObjectMapper objectMapper;
    private final OrgTypeResolver orgTypeResolver;
    private final FeatureFlagService featureFlagService;
    /**
     * Writes each target's row of an automatic deploy, and a manual deploy refused after it was accepted. Both run
     * with no transaction open, so the rows go through the bounded async writer.
     */
    private final CertificateAuditRecorder certificateAudit;

    /** What an automatic (post-issuance / post-renewal) deploy did. */
    public enum AutoDeployOutcome {
        /** Dispatch was attempted for every configured target. */
        DISPATCHED,
        /** No targets, no schedule/config, or an invalid cert: there was nothing to deploy. */
        NOTHING_TO_DEPLOY,
        /** Targets exist but {@code CERTIFICATE_DEPLOYMENT} is off for the organization. */
        SKIPPED_FEATURE_OFF
    }

    /**
     * Dispatch a single deployment target and throw on any failure (manual deploy
     * path).
     *
     * <p>
     * The caller must supply the already-resolved {@code cred} (obtained during
     * pre-validation)
     * and the pre-generated {@code requestId}/{@code correlationId} so that the
     * same IDs can be
     * recorded in audit events before this call.
     *
     * @throws ServiceUnavailableException if the queue publish fails
     */
    public void dispatchSingle(Long organizationId, CertificateEntity cert, String certSecretHandle,
            String credXref, CredentialReferenceEntity cred,
            String requestId, String correlationId, String flowType,
            String configJsonOverride) {
        try {
            doDispatch(organizationId, cert, certSecretHandle, credXref, cred,
                    requestId, correlationId, flowType, "manual", configJsonOverride);
        } catch (RuntimeException e) {
            // The member's deployment.requested row committed before this dispatch: its failure is a row of its own
            // (the request's @AuditFailure is suppressed once a success committed).
            certificateAudit.deploymentDispatchFailed(cert, cred.getProvider(), flowType, dispatchFailureReason(e));
            throw e;
        }
    }

    /**
     * Dispatch one deployment per target credential.
     *
     * <p>Invalid credentials (inactive, wrong type) are logged and skipped.
     * queue publish failures are logged and skipped. Remaining targets are always attempted.
     *
     * <p>AKAMAI_CPS targets receive special handling:
     * <ul>
     *   <li>Manual certs (no DNS credentials) → logged and skipped; Akamai requires
     *       a CA-issued cert signed against a CSR that Akamai generates, which requires
     *       DNS-01 automation.</li>
     *   <li>Case 2.1: An active {@code AKAMAI_CPS} special cert already exists for this
     *       UDC → deploy that cert to the Akamai credential directly.</li>
     *   <li>Case 2.2: No active Akamai-special cert (never issued, expired, or failed)
     *       but an active non-special cert exists → trigger Akamai-special issuance.
     *       Deployment will occur automatically after the agent responds.</li>
     * </ul>
     */
    public void dispatchAll(Long organizationId, CertificateEntity cert, String certSecretHandle,
            List<String> credXrefs, String flowType) {
        // Each target gets its own requestId — deployments.request_id is UNIQUE, and one
        // upstream issuance/renewal can fan out to N deployment targets. The upstream id (the
        // renewal/issuance requestId) remains in MDC for correlation; we swap it for the
        // per-target id only around the actual publish so the log line shows the target's id,
        // then restore it for any code that runs after this loop.
        String parentRequestId = MDC.get("requestId");
        // correlationId is frontend-owned; pull from MDC once. Null on scheduler-driven
        // calls per the "non-HTTP → no corr" convention. Shared across all targets of a
        // single logical user transaction.
        String correlationId = MdcIds.correlationId();
        try {
            // A bulk operation that can partly succeed: every target's outcome is its own row, a failed one with
            // its reason, written explicitly here (never through a request-level @AuditFailure).
            for (String credXref : credXrefs) {
                String targetRequestId = mintTargetRequestId();
                MDC.put("requestId", targetRequestId);
                CredentialReferenceEntity cred = null;
                try {
                    cred = resolveActiveCred(organizationId, credXref);
                    if (!"DEPLOYMENT".equals(cred.getType())) {
                        log.error("[dispatchAll] credXref='{}' is not type DEPLOYMENT for xref={} — skipping",
                                credXref, cert.getCertificateXref());
                        certificateAudit.deploymentDispatchFailed(cert, null, flowType, CREDENTIAL_INVALID);
                        continue;
                    }
                    if (AkamaiSpecialIssuanceService.AKAMAI_CPS.equals(cred.getProvider())) {
                        handleAkamaiCpsTarget(organizationId, cert, cred, credXref, flowType,
                                targetRequestId, correlationId);
                        continue;
                    }
                    doDispatch(organizationId, cert, certSecretHandle, credXref, cred,
                            targetRequestId, correlationId, flowType, "auto", null);
                    certificateAudit.autoDeployStarted(cert, cred.getProvider(), flowType);
                    log.info("[dispatchAll] Deployment published: xref={}, credXref={}, targetType={}",
                            cert.getCertificateXref(), credXref, cred.getProvider());
                } catch (Exception e) {
                    // doDispatch already called markPublishFailed before rethrowing;
                    // for pre-dispatch failures (inactive cred), there is no tracking record.
                    log.error("[dispatchAll] Failed to publish for xref={}, credXref={}: {}",
                            cert.getCertificateXref(), credXref, e.getMessage(), e);
                    certificateAudit.deploymentDispatchFailed(cert, cred == null ? null : cred.getProvider(), flowType,
                            cred == null ? credentialFailureReason(e) : dispatchFailureReason(e));
                }
            }
        } finally {
            // Restore the upstream requestId so any code that runs after dispatchAll
            // (continued handleRenewalSuccess / handleIssuanceSuccess work, response
            // processor cleanup, etc.) logs under the original id.
            if (parentRequestId != null) {
                MDC.put("requestId", parentRequestId);
            } else {
                MDC.remove("requestId");
            }
        }
    }

    /** A deployment credential that is not one (the wrong type, or no longer active). */
    static final AuditReason CREDENTIAL_INVALID = AuditReason.of("DEPLOYMENT_CREDENTIAL_INVALID");

    /**
     * The reason a target's dispatch failed, by the failure's type only (never its message): the agent could not
     * be reached, the deployment configuration is incomplete, or anything else ({@link AuditReasons#of}).
     */
    static AuditReason dispatchFailureReason(Exception failure) {
        if (failure instanceof ServiceUnavailableException) {
            return AuditReasons.SERVICE_UNAVAILABLE;
        }
        if (failure instanceof BadRequestException) {
            return AuditReason.of(ErrorCodes.DEPLOYMENT_CONFIG_MISSING);
        }
        return AuditReasons.of(failure);
    }

    /** The reason a target's credential could not be used: it no longer exists, or is not active. */
    static AuditReason credentialFailureReason(Exception failure) {
        if (failure instanceof ResourceNotFoundException) {
            return AuditReason.of("DEPLOYMENT_CREDENTIAL_MISSING");
        }
        if (failure instanceof BadRequestException) {
            return CREDENTIAL_INVALID;
        }
        return AuditReasons.of(failure);
    }

    /** Per-deployment-target id. Matches the format used elsewhere (req-prefix + UUID). */
    private static String mintTargetRequestId() {
        return "req-" + UUID.randomUUID();
    }

    /**
     * Handles an AKAMAI_CPS deployment target within {@link #dispatchAll}.
     *
     * <p>Decision tree:
     * <ol>
     *   <li>Manual cert (no DNS config) → block; Akamai requires managed issuance.</li>
     *   <li>Active Akamai-special cert exists → dispatch deployment immediately.</li>
     *   <li>Akamai-special cert is PENDING (issuance already in flight) → skip.</li>
     *   <li>No usable Akamai-special cert → trigger new Akamai-special issuance.</li>
     * </ol>
     */
    private void handleAkamaiCpsTarget(Long organizationId, CertificateEntity regularCert,
                                       CredentialReferenceEntity akamaiCred, String credXref,
                                       String flowType, String targetRequestId, String correlationId) {
        Long udcId = regularCert.getUserDomainCertId();

        // Load the credential config for this UDC to check for DNS credentials
        RenewalScheduleEntity schedule = renewalScheduleRepository
                .findByCertificateXref(regularCert.getCertificateXref())
                .orElse(null);
        if (schedule == null) {
            log.error("[AKAMAI_CPS] No renewal schedule for xref={} — cannot determine DNS credentials, skipping",
                    regularCert.getCertificateXref());
            return;
        }
        DomainCredentialConfigEntity credConfig = domainCredConfigRepository
                .findById(schedule.getDomainCredentialConfigId())
                .orElse(null);
        if (credConfig == null) {
            log.error("[AKAMAI_CPS] No credential config for xref={} — skipping",
                    regularCert.getCertificateXref());
            return;
        }

        // Block manual certs: they have no DNS config → cannot use Akamai CPS
        if (credConfig.getDnsConfig() == null || credConfig.getDnsConfig().isEmpty()) {
            log.error("[AKAMAI_CPS] Certificate xref={} was issued manually (no DNS credentials). " +
                      "Akamai CPS deployment requires a CA-managed cert with DNS credentials. Skipping.",
                    regularCert.getCertificateXref());
            return;
        }

        // Case 2.1: Active Akamai-special cert → deploy it directly
        Optional<CertificateEntity> activeAkamaiCert = certificateRepository
                .findTopByUdcIdAndSpecialTypeAndStatus(
                        udcId, AkamaiSpecialIssuanceService.AKAMAI_CPS, CertificateStatus.ACTIVE.name());
        if (activeAkamaiCert.isPresent()) {
            CertificateEntity akamaiCert = activeAkamaiCert.get();
            String akamaiCertSecretHandle = akamaiCert.getCertSecretHandle();
            if (akamaiCertSecretHandle == null || akamaiCertSecretHandle.isBlank()) {
                log.error("[AKAMAI_CPS] Active Akamai-special cert xref={} has no certSecretHandle — skipping",
                        akamaiCert.getCertificateXref());
                return;
            }
            // Reuse the target id from the caller — this akamai-special dispatch IS the
            // deployment target for this credXref; no need to mint a second one.
            doDispatch(organizationId, akamaiCert, akamaiCertSecretHandle, credXref, akamaiCred,
                    targetRequestId, correlationId, flowType, "auto", null);
            certificateAudit.autoDeployStarted(akamaiCert, akamaiCred.getProvider(), flowType);
            log.info("[AKAMAI_CPS] Dispatched deployment of active special cert xref={} → credXref={}",
                    akamaiCert.getCertificateXref(), credXref);
            return;
        }

        // Check for in-flight issuance (PENDING) — avoid duplicate triggers
        Optional<CertificateEntity> pendingAkamaiCert = certificateRepository
                .findTopByUdcIdAndSpecialTypeAndStatus(
                        udcId, AkamaiSpecialIssuanceService.AKAMAI_CPS, CertificateStatus.PENDING.name());
        if (pendingAkamaiCert.isPresent()) {
            log.info("[AKAMAI_CPS] Akamai-special cert already PENDING xref={} — issuance in-flight, skipping trigger",
                    pendingAkamaiCert.get().getCertificateXref());
            return;
        }

        // Case 2.2: No usable Akamai-special cert → trigger new issuance
        log.info("[AKAMAI_CPS] No active Akamai-special cert for udcId={} — triggering new special issuance",
                udcId);
        try {
            akamaiSpecialIssuanceService.triggerAkamaiSpecialIssuance(
                    organizationId, regularCert, schedule, credConfig, akamaiCred);
        } catch (Exception e) {
            log.error("[AKAMAI_CPS] Failed to trigger Akamai-special issuance for xref={}: {}",
                    regularCert.getCertificateXref(), e.getMessage(), e);
        }
    }

    /**
     * Whether automatic deploys may run for the organization: FEATURE_WORK, so it obeys
     * {@code CERTIFICATE_DEPLOYMENT} (cached). The caller records the skip and tells the customer.
     */
    public boolean isAutoDeployEnabled(Long organizationId) {
        return featureFlagService.isEnabled(FeatureFlags.CERTIFICATE_DEPLOYMENT, organizationId);
    }

    /**
     * What an automatic deploy of {@code cert} would do, without dispatching anything: reads its
     * schedule, its {@code domain_credential_config} and the targets there. Lets the issuance and
     * renewal handlers decide inside their transaction whether a skip must be recorded, and dispatch
     * only after it commits.
     *
     * @param deploymentEnabled whether {@code CERTIFICATE_DEPLOYMENT} is on for the organization; the
     *                          caller decides how fresh that answer must be
     * @return {@link AutoDeployOutcome#DISPATCHED} when a dispatch would go out,
     *         {@link AutoDeployOutcome#SKIPPED_FEATURE_OFF} when targets exist but deployment is off,
     *         {@link AutoDeployOutcome#NOTHING_TO_DEPLOY} otherwise
     */
    public AutoDeployOutcome planAutoDeploy(CertificateEntity cert, boolean deploymentEnabled) {
        if (autoDeployTargets(cert, "planAutoDeploy").isEmpty()) {
            return AutoDeployOutcome.NOTHING_TO_DEPLOY;
        }
        return deploymentEnabled ? AutoDeployOutcome.DISPATCHED : AutoDeployOutcome.SKIPPED_FEATURE_OFF;
    }

    /**
     * Auto-deploy after issuance / renewal.
     *
     * <p>
     * Reads the live deployment_targets from domain_credential_config and calls
     * {@link #dispatchAll}. Guards (missing schedule, missing config, empty
     * targets) are
     * logged and cause an early return — they do not throw. When targets exist but
     * {@code CERTIFICATE_DEPLOYMENT} is off for the cert's organization nothing is dispatched (the
     * renewal itself already happened) and {@link AutoDeployOutcome#SKIPPED_FEATURE_OFF} is returned.
     *
     * @return what happened, so the caller can record a skip
     */
    public AutoDeployOutcome dispatchForCert(CertificateEntity cert, String certSecretHandle,
            String organizationId, String flowType) {
        List<String> targets = autoDeployTargets(cert, flowType);
        if (targets.isEmpty()) {
            return AutoDeployOutcome.NOTHING_TO_DEPLOY;
        }
        Long orgId = Long.parseLong(organizationId);
        if (!isAutoDeployEnabled(orgId)) {
            log.info("[dispatchForCert] CERTIFICATE_DEPLOYMENT is off for org={} — not deploying xref={} to {} target(s) "
                    + "(flowType={})", orgId, cert.getCertificateXref(), targets.size(), flowType);
            return AutoDeployOutcome.SKIPPED_FEATURE_OFF;
        }
        dispatchAll(orgId, cert, certSecretHandle, targets, flowType);
        return AutoDeployOutcome.DISPATCHED;
    }

    /**
     * The deployment targets an automatic deploy of {@code cert} goes to; empty (logged) when the cert
     * is not valid any more, or has no schedule, configuration or targets.
     */
    private List<String> autoDeployTargets(CertificateEntity cert, String flowType) {
        // Defensive: auto-deploy assumes the just-issued/renewed cert is valid. Guard against
        // stale responses (DLQ replay, long-delayed agent callback) or a CA returning a cert
        // whose validTo is already past — we should never deploy an already-expired cert.
        if (cert.getValidTo() == null
                || cert.getValidTo().isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            log.warn("[dispatchForCert] Skipping auto-deploy for xref={} — validTo={} is null or in the past (flowType={})",
                    cert.getCertificateXref(), cert.getValidTo(), flowType);
            return List.of();
        }
        RenewalScheduleEntity schedule = renewalScheduleRepository
                .findByCertificateXref(cert.getCertificateXref())
                .orElse(null);
        if (schedule == null) {
            log.warn("[dispatchForCert] No renewal schedule for xref={} — skipping",
                    cert.getCertificateXref());
            return List.of();
        }
        DomainCredentialConfigEntity credConfig = domainCredConfigRepository
                .findById(schedule.getDomainCredentialConfigId())
                .orElse(null);
        if (credConfig == null) {
            log.warn("[dispatchForCert] No domain_credential_config for xref={} — skipping",
                    cert.getCertificateXref());
            return List.of();
        }
        List<String> targets = credConfig.getDeploymentTargets();
        if (targets == null || targets.isEmpty()) {
            log.info("[dispatchForCert] No deployment targets for xref={} — cert stays ACTIVE",
                    cert.getCertificateXref());
            return List.of();
        }
        return targets;
    }

    /**
     * Records a successful agent deployment response.
     *
     * @deprecated A validly signed message can name another organization's requestId; the caller
     * must pass the verified organization so the lookup is scoped to it. Retained only for messages
     * accepted while signature enforcement is off, where no organization can be proven.
     */
    @Deprecated
    public void handleAgentSuccess(String requestId, String targetResourceId,
            OffsetDateTime respondedAt) {
        trackingService.markSuccess(requestId, targetResourceId, respondedAt);
    }

    /** Records a successful agent deployment response, scoped to the authenticated organization. */
    public void handleAgentSuccess(String requestId, Long organizationId, String targetResourceId,
            OffsetDateTime respondedAt) {
        trackingService.markSuccess(requestId, organizationId, targetResourceId, respondedAt);
    }

    /**
     * Records a failed agent deployment response.
     *
     * @deprecated See {@link #handleAgentSuccess(String, String, OffsetDateTime)}.
     */
    @Deprecated
    public void handleAgentFailure(String requestId, String errorCode,
            String errorDetail, OffsetDateTime respondedAt) {
        trackingService.markFailed(requestId, errorCode, errorDetail, respondedAt);
    }

    /** Records a failed agent deployment response, scoped to the authenticated organization. */
    public void handleAgentFailure(String requestId, Long organizationId, String errorCode,
            String errorDetail, OffsetDateTime respondedAt) {
        trackingService.markFailed(requestId, organizationId, errorCode, errorDetail, respondedAt);
    }

    /**
     * Looks up a deployment record by requestId.
     *
     * @deprecated See {@link #handleAgentSuccess(String, String, OffsetDateTime)}.
     */
    @Deprecated
    public Optional<DeploymentEntity> findDeployment(String requestId) {
        return trackingService.findByRequestId(requestId);
    }

    /** Looks up a deployment record by requestId, scoped to the authenticated organization. */
    public Optional<DeploymentEntity> findDeployment(String requestId, Long organizationId) {
        return trackingService.findByRequestIdAndOrganizationId(requestId, organizationId);
    }

    // ------------------------------------------------------------------ //
    // Core dispatch (shared by both public entry points)
    // ------------------------------------------------------------------ //

    private void doDispatch(Long organizationId, CertificateEntity cert, String certSecretHandle,
            String credXref, CredentialReferenceEntity cred,
            String requestId, String correlationId, String flowType, String triggeredBy,
            String configJsonOverride) {
        trackingService.createRequested(
                requestId, correlationId, organizationId,
                cert.getCertificateXref(), cert.getUserDomainCertId(),
                credXref, cred.getProvider(), flowType,
                certSecretHandle, cred.getSecretHandle(), Map.of("triggeredBy", triggeredBy));

        String domain = resolveDeploymentDomain(cert);
        ResolvedConfig resolved = resolveConfig(organizationId, cert, cred, configJsonOverride);
        if ("KUBERNETES_SECRETS".equals(cred.getProvider())
                && (resolved.configJson() == null || resolved.configJson().isBlank())) {
            trackingService.markFailed(
                    requestId,
                    ErrorCodes.DEPLOYMENT_CONFIG_MISSING,
                    "Kubernetes deployment config not found for certificate and deployment credential",
                    OffsetDateTime.now());
            throw new BadRequestException(
                    "Kubernetes deployment config not found for certificate '" + cert.getCertificateXref() +
                            "' and deployment credential '" + credXref + "'");
        }

        if (TARGETS_REQUIRED_PROVIDERS.contains(cred.getProvider())
                && (resolved.targetsJson() == null || resolved.targetsJson().isBlank())) {
            String detail = cred.getProvider() + " requires deployment targets but none are configured for certificate '"
                    + cert.getCertificateXref() + "' and credential '" + credXref
                    + "'. Add targets via the deployment-targets API before deploying.";
            trackingService.markFailed(requestId, ErrorCodes.DEPLOYMENT_CONFIG_MISSING, detail, OffsetDateTime.now());
            throw new BadRequestException(detail);
        }

        String credentialScopeJson = (cred.getConfigJson() != null && !cred.getConfigJson().isBlank())
                ? cred.getConfigJson() : null;

        CertDeploymentCommand cmd = CertDeploymentCommand.builder()
                .organizationId(organizationId.toString())
                .orgType(orgTypeResolver.resolve(organizationId))
                .requestId(requestId)
                .correlationId(correlationId)
                .certificateXref(cert.getCertificateXref())
                .domain(domain)
                .certSecretHandle(certSecretHandle)
                .targetType(TargetType.valueOf(cred.getProvider()))
                .deploymentCredHandle(cred.getSecretHandle())
                .credentialScopeJson(credentialScopeJson)
                .targetsJson(resolved.targetsJson())
                .configJson(resolved.configJson())
                .build();
        // Intentionally log only non-PII/high-signal fields for the queue publish path.
        log.info("Publishing deployment command to cert agent: domain={}, targetType={}, hasScope={}, hasTargets={}, hasResult={}",
                domain, cred.getProvider(),
                credentialScopeJson != null,
                resolved.targetsJson() != null,
                resolved.configJson() != null);

        try {
            publisher.publishDeployment(cmd);
            trackingService.markPublished(requestId);
        } catch (Exception e) {
            trackingService.markPublishFailed(requestId, ErrorCodes.QUEUE_PUBLISH_FAILED, e.getMessage());
            log.error("queue publish failed for CERT_DEPLOYMENT xref={}: {}",
                    cert.getCertificateXref(), e.getMessage(), e);
            throw new ServiceUnavailableException(
                    "Failed to dispatch deployment command to cert agent. Deployment request " + requestId +
                            " has been marked as PUBLISH_FAILED — please retry.",
                    e);
        }
    }

    // ------------------------------------------------------------------ //
    // Helpers
    // ------------------------------------------------------------------ //

    private CredentialReferenceEntity resolveActiveCred(Long organizationId, String credXref) {
        CredentialReferenceEntity cred = credentialService.getByXref(organizationId, credXref);
        if (!"ACTIVE".equals(cred.getStatus())) {
            throw new BadRequestException(
                    "credentialXref '" + credXref + "' is not ACTIVE for organization");
        }
        return cred;
    }

    private String resolveDeploymentDomain(CertificateEntity cert) {
        if (cert.getDomain() != null && !cert.getDomain().isBlank()) {
            return cert.getDomain();
        }
        if (cert.getUserDomainCertId() != null) {
            return udcRepository.findById(cert.getUserDomainCertId())
                    .map(UserDomainCertEntity::getDomain)
                    .filter(d -> d != null && !d.isBlank())
                    .orElseThrow(() -> new BadRequestException(
                            "Cannot build deployment command for certificate '" + cert.getCertificateXref() +
                                    "' because domain is missing in certificate and user_domain_cert."));
        }
        throw new BadRequestException(
                "Cannot build deployment command for certificate '" + cert.getCertificateXref() +
                        "' because domain is missing and userDomainCertId is null.");
    }

    /**
     * Resolves the on-wire payload split for the deployment command:
     * <ul>
     *   <li>K8s (or any caller with override): legacy flat config goes to {@code configJson}, targets is null.</li>
     *   <li>Non-K8s: reads the persisted envelope and splits it into {@code targetsJson}
     *       ({@code envelope.targets}) and {@code configJson} ({@code envelope.result}, the
     *       agent-friendly flat per-provider shape).</li>
     * </ul>
     */
    private ResolvedConfig resolveConfig(Long organizationId, CertificateEntity cert,
            CredentialReferenceEntity cred, String configJsonOverride) {
        boolean isK8s = "KUBERNETES_SECRETS".equals(cred.getProvider());
        if (isK8s && configJsonOverride != null && !configJsonOverride.isBlank()) {
            log.debug("Ignoring configJson override for Kubernetes deployment: certXref={}, credXref={}",
                    cert.getCertificateXref(), cred.getCredentialXref());
        }

        String storedJson;
        if (!isK8s && configJsonOverride != null && !configJsonOverride.isBlank()) {
            storedJson = configJsonOverride;
        } else {
            Long userDomainCertId = cert.getUserDomainCertId();
            if (userDomainCertId == null || cred.getId() == null) {
                return new ResolvedConfig(null, null);
            }
            storedJson = certDeploymentConfigService
                    .findReconciledConfigJson(organizationId, userDomainCertId, cred)
                    .orElse(null);
        }

        if (storedJson == null || storedJson.isBlank()) {
            return new ResolvedConfig(null, null);
        }

        // Kubernetes preserves its legacy flat shape — pass it through as-is on the wire.
        if (isK8s) {
            return new ResolvedConfig(null, storedJson);
        }

        // Non-K8s: split the envelope. Targets go on the wire as `targetsJson`; the result
        // slice goes as the (flat) `configJson` agents already understand.
        DeploymentConfigEnvelope envelope = DeploymentConfigEnvelope.read(objectMapper, storedJson);
        String targetsJson = jsonOrNull(envelope.targets());
        String resultJson  = jsonOrNull(envelope.result());
        return new ResolvedConfig(targetsJson, resultJson);
    }

    private String jsonOrNull(JsonNode node) {
        if (node == null || !node.isObject() || node.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception e) {
            log.warn("Failed to serialize deployment config slice — sending null on wire: {}", e.getMessage());
            return null;
        }
    }

    private record ResolvedConfig(String targetsJson, String configJson) {}
}
