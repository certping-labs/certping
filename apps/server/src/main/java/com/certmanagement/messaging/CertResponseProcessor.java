// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.service.cert.RenewalTiming;

import com.certmanagement.enums.KeyCustody;
import com.certmanagement.service.cert.CaOrderCostValue;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.entity.CertManualIssuanceStateEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.iot.messaging.DeviceIdentitySyncResponseComplete;
import com.certmanagement.iot.messaging.DeviceIdentitySyncResponsePart;
import com.certmanagement.iot.messaging.DeviceSourceHealthMessage;
import com.certmanagement.iot.messaging.IotIdentitySyncResponseHandler;
import com.certmanagement.iot.cahealth.CaHealthReportMessage;
import com.certmanagement.iot.cahealth.IotCaHealthService;
import com.certmanagement.iot.revocation.IotCertificateRevocationResult;
import com.certmanagement.iot.revocation.IotRevocationResultService;
import com.certmanagement.iot.revocation.IotIntuneRevocationPollResult;
import com.certmanagement.iot.revocation.IotIntuneRevocationUploadResult;
import com.certmanagement.iot.revocation.IotIntuneRevocationWorkflow;
import com.certmanagement.iot.certificate.IotCertificateIngestionService;
import com.certmanagement.iot.certificate.IotDeviceNudgeResultService;
import com.certmanagement.iot.messaging.IotDeviceSyncResult;
import com.certmanagement.iot.certificate.ScepCertRequestedMessage;
import com.certmanagement.iot.certificate.ScepCertResultMessage;
import com.certmanagement.iot.certificate.ScepCertificateIssuedMessage;
import com.certmanagement.iot.profile.CertificateProfileOperationResponse;
import com.certmanagement.iot.profile.CertificateProfileResponseHandler;
import com.certmanagement.iot.profile.CertificateProfileSyncResponseComplete;
import com.certmanagement.iot.profile.CertificateProfileSyncResponsePart;
import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.messaging.model.AgentDeepHealthCheckResponse;
import com.certmanagement.messaging.model.AgentHealthHeartbeat;
import com.certmanagement.messaging.model.CertDeploymentResponse;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.messaging.model.CertSecretDeleteResponse;
import com.certmanagement.messaging.model.CertManualTxtResponse;
import com.certmanagement.messaging.model.CertRevocationResponse;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.entity.AlertEntity;
import com.certmanagement.messaging.security.AgentMessageVerificationException;
import com.certmanagement.messaging.security.VerifiedAgentMessage;
import com.certmanagement.constants.ErrorCodes;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.UnknownOrganizationForHeartbeatException;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.enums.EventSource;
import com.certmanagement.enums.RenewalStatus;
import com.certmanagement.enums.AlertSeverity;
import com.certmanagement.enums.AlertStatus;
import com.certmanagement.enums.AlertTypeEnum;
import com.certmanagement.entity.CertificateCryptoMetadataEntity;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateCryptoMetadataRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.cert.AbandonedRenewalCleanup;
import com.certmanagement.service.cert.AkamaiSpecialIssuanceService;
import com.certmanagement.service.AlertService;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.cert.RenewalRetryPolicy;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.agent.AgentHealthService;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.iot.service.IotDeviceSourceHealthService;
import com.certmanagement.service.discovery.DiscoveryService;
import com.certmanagement.util.UserFacingErrorMessages;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Metrics;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Processes agent results from the cert-agent-outbound queue (see {@link QueueAgentResponseWorker}).
 *
 * <p><b>ACK / notification ordering</b>: {@code onComplete} is called <em>after</em> the DB work
 * succeeds but <em>before</em> the notification publish is attempted.
 *
 * <p>Routing logic:
 * <pre>
 *   MessageType = CERT_ISSUANCE_RESPONSE, status = ISSUED  → handleIssuanceSuccess
 *   MessageType = CERT_ISSUANCE_RESPONSE, status = RENEWED → handleRenewalSuccess
 *   MessageType = CERT_DEPLOYMENT_RESPONSE                 → handleDeploymentSuccess
 *   MessageType = CERT_REVOCATION_RESPONSE                 → handleRevocationResponse
 *   MessageType = CERT_SECRET_DELETE_RESPONSE                  → handleKvDeleteResponse
 *   MessageType = AGENT_ERROR                              → handleAgentError
 * </pre>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertResponseProcessor {

    private final CertificateRepository               certificateRepository;
    private final CertificateCryptoMetadataRepository  cryptoMetadataRepository;
    private final CertificateEventRepository           eventRepository;
    private final RenewalScheduleRepository            renewalScheduleRepository;
    private final DomainCredentialConfigRepository     domainCredConfigRepository;
    private final CertManualIssuanceStateRepository    manualIssuanceStateRepository;
    private final CertIssuanceService                  certIssuanceService;
    private final NotificationPublisher                notificationPublisher;
    private final AlertService                         alertService;
    private final ObjectMapper                         objectMapper;
    private final DeploymentExecutionService           deploymentExecutionService;
    private final CertDeploymentConfigService         certDeploymentConfigService;
    private final CredentialReferenceRepository        credentialReferenceRepository;
    private final AgentHealthService                   agentHealthService;
    private final AgentDeepHealthCheckService          agentDeepHealthCheckService;
    private final DiscoveryService                     discoveryService;
    private final IotIdentitySyncResponseHandler       iotIdentitySyncResponseHandler;
    private final IotDeviceSourceHealthService         iotDeviceSourceHealthService;
    private final CertificateProfileResponseHandler    certificateProfileResponseHandler;
    private final IotCertificateIngestionService       iotCertificateIngestionService;
    private final IotDeviceNudgeResultService           iotDeviceNudgeResultService;
    private final IotCaHealthService                    iotCaHealthService;
    private final IotRevocationResultService            iotRevocationResultService;
    private final IotIntuneRevocationWorkflow           iotIntuneRevocationWorkflow;
    /** Issuance/renewal successes run in one explicit transaction (see handleIssuanceSuccess). */
    private final TransactionTemplate                  transactionTemplate;
    private final FeatureLifecycleLock                 featureLifecycleLock;
    private final FeatureFlagResolver                  featureFlagResolver;
    private final DeploymentRepository                 deploymentRepository;
    /**
     * Writes what the agent reported (issued, renewed, revoked, deployed, failed) and what CertPing skipped, as
     * CertPing (AuditScope.system) on behalf of the member whose request it answers. Every row is written in a
     * transaction together with the certificate's timeline event, and only when that event was new, so a
     * redelivered response writes no second row.
     */
    private final CertificateAuditRecorder             certificateAudit;

    /** Customer notification when a renewed cert was not deployed because deployment is off. */
    static final String CERT_RENEWED_NOT_DEPLOYED = "CERT_RENEWED_NOT_DEPLOYED";

    /** Flow types of the automatic deploys after a success, as recorded on their deployments. */
    static final String FLOW_POST_ISSUANCE = "AUTO_POST_ISSUANCE";
    static final String FLOW_POST_RENEWAL = "AUTO_POST_RENEWAL";
    static final String FLOW_POST_AKAMAI_ISSUANCE = "AUTO_POST_AKAMAI_ISSUANCE";

    /** The automatic deploy a committed success dispatches: which handle, for which org, in which flow. */
    private record DeployIntent(String certSecretHandle, String organizationId, String flowType, boolean akamai) {}

    /** What a success's automatic deploy does: dispatch {@code intent}, nothing, or skip (deployment off). */
    private record DeployDecision(DeployIntent intent, boolean skippedFeatureOff) {
        static final DeployDecision NONE = new DeployDecision(null, false);
        static final DeployDecision SKIPPED_FEATURE_OFF = new DeployDecision(null, true);
    }

    /**
     * The immutable result of an issuance/renewal success transaction, acted on after it commits.
     *
     * @param transitioned  this delivery applied the response; false when an earlier delivery had
     * @param deploy        the deploy to dispatch after commit, or null
     * @param notification  the notifications to publish (follow-ups chained)
     * @param notDeployed   the "renewed, not deployed" email to add if the post-commit dispatch finds
     *                      deployment switched off meanwhile (renewals only), or null
     */
    private record SuccessOutcome(boolean transitioned, boolean renewal, String certificateXref, String requestId,
                                  String correlationId, DeployIntent deploy, NotifPayload notification,
                                  NotifPayload notDeployed) {
        static final SuccessOutcome NOTHING = new SuccessOutcome(false, false, null, null, null, null, null, null);
    }

    /**
     * Carries the notification payload back from each handler for post-ACK dispatch.
     * {@code followUp} is a second notification for the same message (published after this one),
     * or {@code null}.
     */
    private record NotifPayload(String action, String organizationId, String certXref,
                                Map<String, Object> details, NotifPayload followUp) {
        NotifPayload(String action, String organizationId, String certXref, Map<String, Object> details) {
            this(action, organizationId, certXref, details, null);
        }

        NotifPayload withFollowUp(NotifPayload next) {
            return next == null ? this : new NotifPayload(action, organizationId, certXref, details, next);
        }
    }

    /**
     * The organization to act as: the proven one when the message was authenticated, otherwise
     * the body's claim. Handlers must never read the organization straight out of the payload
     * while a verified one is available.
     */
    private Long organizationOf(String bodyOrganizationId, VerifiedAgentMessage verified) {
        // The declared organization wins whenever there is one: the gateway proved it from the
        // agent's token, and requireBodyOrganizationMatches has already established that it
        // agrees with the body. Falling back to the body only when nothing was declared keeps
        // this in step with findCertificateForOrganization, which scopes on the same value.
        if (verified != null && verified.organizationId() != null
                && !verified.organizationId().isBlank()) {
            return parseOrganizationId(verified.organizationId());
        }
        return parseOrganizationId(bodyOrganizationId);
    }

    /**
     * Loads a certificate, requiring it to belong to the authenticated organization.
     *
     * <p>An authenticated sender proves who sent the message; it does not prove that the
     * {@code certificateXref} inside names one of their certificates. Looking up by xref alone
     * would let an authenticated organization mark another tenant's certificate issued, deployed,
     * revoked or failed, so ownership is part of the query rather than a check afterwards.
     *
     * <p>A cross-tenant reference is a security event, not a normal not-found: it is logged with
     * the verified organization and the xref, and nothing about the other tenant's record is
     * revealed to the caller.
     */
    private Optional<CertificateEntity> findCertificateForOrganization(String xref,
                                                                       VerifiedAgentMessage verified) {
        if (xref == null || xref.isBlank()) {
            return Optional.empty();
        }
        Long organizationId = verified == null ? null : parseOrganizationId(verified.organizationId());
        if (organizationId == null) {
            return certificateRepository.findByCertificateXref(xref);
        }
        Optional<CertificateEntity> scoped =
                certificateRepository.findByCertificateXrefAndOrganizationId(xref, organizationId);
        // Only worth a second query when the sender was authenticated: for an unverified
        // message a miss is routine (the certificate may have been deleted between dispatch
        // and the response arriving), and this would double the work on that path.
        if (scoped.isEmpty() && verified.verified()
                && certificateRepository.findByCertificateXref(xref).isPresent()) {
            log.error("SECURITY: agent message from organizationId={} referenced certificateXref={} "
                            + "owned by a different organization — refusing to process",
                    organizationId, xref);
        }
        return scoped;
    }

    /**
     * Rejects a body whose {@code organizationId} disagrees with the authenticated one.
     *
     * <p>The gateway stamps the organization of the agent token that sent the message, so the two
     * can only diverge if an agent sent a payload naming another tenant. Handlers read ids from the
     * body throughout, so the mismatch is caught once here rather than trusted in twenty places.
     */
    void requireBodyOrganizationMatches(String body, VerifiedAgentMessage verified) {
        // Applied to unverified traffic as well. The claim is not proven there, but certificate
        // lookups are scoped by it while handlers read ids from the body, so the two must agree
        // or a message would be scoped as one tenant and processed as another.
        if (verified == null || verified.organizationId() == null) {
            return;
        }
        try {
            String claimed = objectMapper.readTree(body).path("organizationId").asString("");
            if (!claimed.isEmpty() && !claimed.equals(verified.organizationId())) {
                throw AgentMessageVerificationException.rejected("BODY_ORGANIZATION_MISMATCH",
                        "Body organizationId does not match the authenticated organization");
            }
        } catch (AgentMessageVerificationException e) {
            throw e;
        } catch (Exception ignored) {
            // Not JSON, or no organizationId: the authenticated organization remains authoritative.
        }
    }

    /**
     * Entry point, called by {@link QueueAgentResponseWorker} for each received message.
     *
     * <p>{@code verified} carries the organization proven to have sent this message. Handlers scope
     * their lookups to it rather than to the {@code organizationId} in the body, which is
     * sender-controlled.
     */
    void process(String messageType, String body, VerifiedAgentMessage verified,
                 Runnable onComplete, Runnable onAbandon) {
        NotifPayload notif = null;
        try {
            switch (messageType != null ? messageType : "") {
                case "CERT_ISSUANCE_RESPONSE" -> {
                    CertIssuanceResponse response = objectMapper.readValue(body, CertIssuanceResponse.class);
                    boolean renewal = "RENEWED".equals(response.getStatus());
                    Optional<AgentErrorMessage> withoutExpiry = IssuedValidity.missingExpiry(response, renewal);
                    if (withoutExpiry.isPresent()) {
                        log.error("[CERT_ISSUED_WITHOUT_EXPIRY] Agent result has no readable validTo; recorded as a failure. "
                                + "xref={} requestId={} renewal={}", response.getCertificateXref(), response.getRequestId(), renewal);
                        notif = handleAgentError(withoutExpiry.get(), verified);
                    } else {
                        notif = renewal ? handleRenewalSuccess(response, verified) : handleIssuanceSuccess(response, verified);
                    }
                }
                case "CERT_DEPLOYMENT_RESPONSE" -> {
                    CertDeploymentResponse response = objectMapper.readValue(body, CertDeploymentResponse.class);
                    notif = handleDeploymentSuccess(response, verified);
                }
                case "CERT_REVOCATION_RESPONSE" -> {
                    CertRevocationResponse response = objectMapper.readValue(body, CertRevocationResponse.class);
                    notif = handleRevocationResponse(response, verified);
                }
                case "AGENT_ERROR" -> {
                    AgentErrorMessage error = objectMapper.readValue(body, AgentErrorMessage.class);
                    notif = handleAgentError(error, verified);
                }
                case "AGENT_HEALTH_HEARTBEAT" -> {
                    AgentHealthHeartbeat heartbeat = objectMapper.readValue(body, AgentHealthHeartbeat.class);
                    handleAgentHealthHeartbeat(heartbeat);
                    if (heartbeat.getCaStatus() != null && verified != null) {
                        agentHealthService.saveCaStatus(verified.organizationId(), verified.agentTokenId(),
                                heartbeat.getCaStatus());
                    }
                    if (verified != null) {
                        agentHealthService.saveAgentInfo(verified.organizationId(), verified.agentTokenId(),
                                heartbeat.getAgentInfo());
                    }
                    // Organization-admin notifications are intentionally deferred for a later phase.
                }
                case "AGENT_DEEP_HEALTH_CHECK_RESPONSE" -> {
                    AgentDeepHealthCheckResponse response = objectMapper.readValue(body, AgentDeepHealthCheckResponse.class);
                    agentDeepHealthCheckService.ingestResponse(response);
                }
                case "AGENT_CA_HEALTH_REPORT" -> {
                    CaHealthReportMessage report = objectMapper.readValue(body, CaHealthReportMessage.class);
                    iotCaHealthService.handle(report);
                }
                case "SCEP_CERT_REQUESTED" -> {
                    ScepCertRequestedMessage requested = objectMapper.readValue(
                            body, ScepCertRequestedMessage.class);
                    iotCertificateIngestionService.handleRequested(requested);
                }
                case "SCEP_CERT_ISSUED" -> {
                    ScepCertificateIssuedMessage issued = objectMapper.readValue(
                            body, ScepCertificateIssuedMessage.class);
                    iotCertificateIngestionService.handle(issued);
                }
                case "SCEP_CERT_RESULT" -> {
                    ScepCertResultMessage result = objectMapper.readValue(
                            body, ScepCertResultMessage.class);
                    iotCertificateIngestionService.handleResult(result);
                }
                case "IOT_DEVICE_SYNC_RESPONSE" -> {
                    IotDeviceSyncResult result = objectMapper.readValue(body, IotDeviceSyncResult.class);
                    iotDeviceNudgeResultService.handle(result);
                }
                case "IOT_CERTIFICATE_REVOCATION_RESULT" -> {
                    IotCertificateRevocationResult result = objectMapper.readValue(
                            body, IotCertificateRevocationResult.class);
                    iotRevocationResultService.handle(result);
                }
                case "IOT_INTUNE_REVOCATION_POLL_RESULT" -> {
                    IotIntuneRevocationPollResult result = objectMapper.readValue(
                            body, IotIntuneRevocationPollResult.class);
                    iotIntuneRevocationWorkflow.handlePollResult(result);
                }
                case "IOT_INTUNE_REVOCATION_UPLOAD_RESULT" -> {
                    IotIntuneRevocationUploadResult result = objectMapper.readValue(
                            body, IotIntuneRevocationUploadResult.class);
                    iotIntuneRevocationWorkflow.handleUploadResult(result);
                }
                case "IOT_DEVICE_SOURCE_HEALTH" -> {
                    DeviceSourceHealthMessage health =
                            objectMapper.readValue(body, DeviceSourceHealthMessage.class);
                    iotDeviceSourceHealthService.handle(health, verified == null ? null : verified.agentTokenId());
                }
                case "CERT_MANUAL_TXT_RESPONSE" -> {
                    CertManualTxtResponse response = objectMapper.readValue(body, CertManualTxtResponse.class);
                    notif = handleManualTxtResponse(response, verified);
                }
                case "CERT_SECRET_DELETE_RESPONSE" -> {
                    CertSecretDeleteResponse response = objectMapper.readValue(body, CertSecretDeleteResponse.class);
                    handleKvDeleteResponse(response);
                }
                case "CERT_DISCOVERY_RESPONSE" -> {
                    CertDiscoveryResponse response = objectMapper.readValue(body, CertDiscoveryResponse.class);
                    log.info("CERT_DISCOVERY_RESPONSE arrived: organizationId={}, requestId={}, batch={}/{}, certs={}",
                            response.getOrganizationId(), response.getRequestId(),
                            response.getBatchIndex() + 1, response.getTotalBatches(),
                            response.getDiscoveredCerts() != null ? response.getDiscoveredCerts().size() : 0);
                    discoveryService.persistDiscoveryResults(response,
                            organizationOf(response.getOrganizationId(), verified));
                }
                case "CERT_DISCOVERY_COMPLETE" -> {
                    DiscoveryCompleteMessage msg = objectMapper.readValue(body, DiscoveryCompleteMessage.class);
                    log.info("CERT_DISCOVERY_COMPLETE: requestId={}, organizationId={}, totalCerts={}",
                            msg.getRequestId(), msg.getOrganizationId(), msg.getTotalCerts());
                    discoveryService.markDiscoveryComplete(msg);
                }
                case "DEVICE_IDENTITY_SYNC_RESPONSE_PART" -> {
                    DeviceIdentitySyncResponsePart part =
                            objectMapper.readValue(body, DeviceIdentitySyncResponsePart.class);
                    log.info("DEVICE_IDENTITY_SYNC_RESPONSE_PART: organizationId={}, source={}, batch={}, devices={}",
                            part.getOrganizationId(), part.getSourceXref(), part.getBatchIndex(),
                            part.getDevices() != null ? part.getDevices().size() : 0);
                    try {
                        iotIdentitySyncResponseHandler.handlePart(part);
                    } catch (RuntimeException e) {
                        iotIdentitySyncResponseHandler.markProcessingFailed(part.getOrganizationId(),
                                part.getSourceXref(), part.getSyncXref(), part.getCorrelationId(), e);
                        throw e;
                    }
                }
                case "DEVICE_IDENTITY_SYNC_RESPONSE_COMPLETE" -> {
                    DeviceIdentitySyncResponseComplete complete =
                            objectMapper.readValue(body, DeviceIdentitySyncResponseComplete.class);
                    log.info("DEVICE_IDENTITY_SYNC_RESPONSE_COMPLETE: organizationId={}, source={}, mode={}, totalDevices={}",
                            complete.getOrganizationId(), complete.getSourceXref(),
                            complete.getMode(), complete.getTotalDevices());
                    try {
                        iotIdentitySyncResponseHandler.handleComplete(complete);
                    } catch (RuntimeException e) {
                        iotIdentitySyncResponseHandler.markProcessingFailed(complete.getOrganizationId(),
                                complete.getSourceXref(), complete.getSyncXref(), complete.getCorrelationId(), e);
                        throw e;
                    }
                }
                case "IOT_CERTIFICATE_PROFILE_RESPONSE" -> {
                    CertificateProfileOperationResponse response = objectMapper.readValue(
                            body, CertificateProfileOperationResponse.class);
                    certificateProfileResponseHandler.handleOperation(response);
                }
                case "IOT_CERTIFICATE_PROFILE_SYNC_RESPONSE_PART" -> {
                    CertificateProfileSyncResponsePart part = objectMapper.readValue(
                            body, CertificateProfileSyncResponsePart.class);
                    certificateProfileResponseHandler.handlePart(part);
                }
                case "IOT_CERTIFICATE_PROFILE_SYNC_RESPONSE_COMPLETE" -> {
                    CertificateProfileSyncResponseComplete complete = objectMapper.readValue(
                            body, CertificateProfileSyncResponseComplete.class);
                    certificateProfileResponseHandler.handleComplete(complete);
                }
                default -> log.warn("Received unknown MessageType '{}' — ignoring", messageType);
            }
            onComplete.run();
        } catch (Exception e) {
            log.error("Failed to process {} message: {}", messageType, e.getMessage(), e);
            onAbandon.run();
            return;
        }
        for (NotifPayload next = notif; next != null; next = next.followUp()) {
            try {
                notificationPublisher.publish(
                        next.action(), next.organizationId(), next.certXref(), next.details());
            } catch (Exception e) {
                log.error("Notification publish failed for action={}, xref={}: {}",
                        next.action(), next.certXref(), e.getMessage(), e);
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  Private handlers
    // ------------------------------------------------------------------ //

    // ------------------------------------------------------------------ //
    //  Issuance / renewal success
    //
    //  Each response is applied in ONE transaction whose first statements take the
    //  CERTIFICATE_RENEWAL and CA feature locks (so it serializes with an org admin's
    //  DISABLE_AUTO_RENEW clear and switch-off), re-read those flags past the cache, and then
    //  record the certificate, its renewal schedule and every event. The deploy dispatch runs
    //  only after that commits, and process() publishes the notifications after the message is
    //  acknowledged: no lock or transaction spans a call to the message queue.
    //
    //  A redelivered response that an earlier delivery already applied writes nothing. It re-runs
    //  the dispatch only when no deployment was recorded for the certificate and flow yet (never
    //  deploying twice), and re-publishes the same notifications under the same request ids,
    //  which the notifier delivers once.
    // ------------------------------------------------------------------ //

    private NotifPayload handleIssuanceSuccess(CertIssuanceResponse response, VerifiedAgentMessage verified) {
        log.info("CERT_ISSUANCE_RESPONSE (ISSUED): xref={}", response.getCertificateXref());
        try (AuditScope scope = agentScope(response.getOrganizationId(), verified, response.getCorrelationId())) {
            SuccessOutcome outcome = transactionTemplate.execute(status -> applyIssuance(response, verified));
            return completeAfterCommit(outcome, verified);
        }
    }

    private SuccessOutcome applyIssuance(CertIssuanceResponse response, VerifiedAgentMessage verified) {
        AutoRenewFeatureLocks locks = lockAutoRenewFeatures(response, verified);
        String xref = response.getCertificateXref();
        Optional<CertificateEntity> optCert = findCertificateForOrganization(xref, verified);
        if (optCert.isEmpty()) {
            log.error("Certificate not found for xref={} — ignoring response", xref);
            return SuccessOutcome.NOTHING;
        }
        CertificateEntity cert = optCert.get();
        String prevStatus = cert.getStatus();

        if (CertificateStatus.CANCELLED_MANUAL.name().equals(prevStatus)) {
            log.warn("Ignoring CERT_ISSUANCE_RESPONSE for cancelled manual flow xref={}", xref);
            manualIssuanceStateRepository.deleteByCertXref(xref);
            return SuccessOutcome.NOTHING;
        }
        Long organizationId = cert.getOrganizationId();
        holdCertificateLocks(locks, organizationId, cert.getCaProvider());
        if (isIssuanceAlreadyApplied(cert, response)) {
            log.info("Issuance of xref={} (serial={}) was already applied — replaying the post-commit work only",
                    xref, response.getSerialNumber());
            return replayOutcome(cert, response, organizationId, false,
                    issuanceSuccessNotification(cert, response), null);
        }

        demoteSupersededActive(cert, response);
        applyIssuedFields(cert, response);
        certificateRepository.save(cert);
        upsertCryptoMetadata(xref, response);

        // Clean up ephemeral manual issuance state if present (manual flow only).
        // No-op for automated issuance — deleteByCertXref is safe on non-existent rows.
        manualIssuanceStateRepository.deleteByCertXref(xref);

        if (CaProvider.LETS_ENCRYPT == cert.getCaProvider() && cert.getAcmeAccountHandle() == null) {
            log.error("LETS_ENCRYPT cert xref={} saved as ACTIVE but acmeAccountHandle is null — " +
                      "future renewals will create a new ACME account (rate-limit risk)!", xref);
        }

        List<String> autoRenewOff = autoRenewFeaturesOff(organizationId, cert.getCaProvider());
        boolean scheduleEnabled = enableIssuedSchedule(cert, response, autoRenewOff);

        if (insertEvent(xref, cert.getOrganizationId(), CertEventType.ISSUANCE_SUCCESS.name(), prevStatus,
                CertificateStatus.ACTIVE.name(),
                response.getRequestId(), response.getCorrelationId(), EventSource.AGENT.value(),
                Map.of("domain", orEmpty(cert.getDomain()), "issuer", orEmpty(response.getIssuer()),
                       "validTo", orEmpty(response.getValidTo())))) {
            certificateAudit.issued(cert, requestedBy(response.getRequestId()), cert.getSpecialCertificateType());
        }
        recordAutoRenewSkipped(cert, response, autoRenewOff, scheduleEnabled, FLOW_POST_ISSUANCE);

        DeployDecision deploy = decideDeploy(cert, response, organizationId, false, false);
        if (deploy.skippedFeatureOff()) {
            // The org just issued it (UI shows it), so the event is enough; no extra email.
            recordAutoDeploySkipped(cert, response.getRequestId(), response.getCorrelationId(), FLOW_POST_ISSUANCE);
        }
        return new SuccessOutcome(true, false, xref, response.getRequestId(), response.getCorrelationId(),
                deploy.intent(), issuanceSuccessNotification(cert, response), null);
    }

    /**
     * Retries can create a fresh issuance row while an older cert for the same domain remains
     * ACTIVE. Demotes that prior ACTIVE row first to satisfy the one-active-per-UDC unique
     * constraint before this cert is promoted.
     */
    private void demoteSupersededActive(CertificateEntity cert, CertIssuanceResponse response) {
        String xref = cert.getCertificateXref();
        findActiveByUserDomainCertId(cert.getUserDomainCertId())
            .filter(active -> !xref.equals(active.getCertificateXref()))
            .ifPresent(active -> {
                String previousActiveStatus = active.getStatus();
                active.setStatus(CertificateStatus.RENEW_SUCCESS.name());
                active.setLastErrorCode(null);
                active.setLastErrorMessage(null);
                active.setLastErrorAt(null);
                certificateRepository.save(active);

                renewalScheduleRepository.findByCertificateXref(active.getCertificateXref())
                    .ifPresent(rs -> {
                    rs.setEnabled(false);
                    renewalScheduleRepository.save(rs);
                    });

                insertEvent(
                    active.getCertificateXref(),
                    active.getOrganizationId(),
                    CertEventType.STATUS_CHANGED.name(),
                    previousActiveStatus,
                    CertificateStatus.RENEW_SUCCESS.name(),
                    response.getRequestId(),
                    response.getCorrelationId(),
                    EventSource.AGENT.value(),
                    Map.of(
                        "reason", "superseded_by_reissue",
                        "replacedByCertificateXref", xref));
            });
    }

    /** Copies what the CA issued onto the certificate and makes it ACTIVE; the caller saves it. */
    private void applyIssuedFields(CertificateEntity cert, CertIssuanceResponse response) {
        cert.setStatus(CertificateStatus.ACTIVE.name());
        cert.setIssuer(response.getIssuer());
        cert.setSerialNumber(response.getSerialNumber());
        cert.setFingerprintSha256(response.getFingerprintSha256());
        cert.setValidFrom(IssuedValidity.parse(response.getValidFrom()));
        cert.setValidTo(IssuedValidity.parse(response.getValidTo()));
        cert.setSignatureAlgorithm(response.getSignatureAlgorithm());
        cert.setPublicKeyAlgorithm(response.getPublicKeyAlgorithm());
        cert.setKeySize(response.getKeySize());
        cert.setCertType(response.getCertType());
        if (response.getCertSecretHandle() != null && !response.getCertSecretHandle().isBlank()) {
            cert.setCertSecretHandle(response.getCertSecretHandle());
        }
        if (response.getAcmeAccountHandle() != null) {
            cert.setAcmeAccountHandle(response.getAcmeAccountHandle());
        }
        if (response.getOrderId() != null && !response.getOrderId().isBlank()) {
            cert.setOrderId(response.getOrderId());
        }
        CaOrderCostValue.parse(response.getCaOrderCost(), response.getCaOrderCurrency()).ifPresent(cost -> {
            cert.setCaOrderCost(cost.amount());
            cert.setCaOrderCurrency(cost.currency());
        });
        KeyCustody.fromResponse(response.getKeyCustody()).ifPresent(cert::setKeyCustody);
        cert.setLastErrorCode(null);
        cert.setLastErrorMessage(null);
        cert.setLastErrorAt(null);
    }

    /**
     * Points the issued certificate's renewal schedule at what was issued and turns automatic renewal
     * on, unless a feature in {@code autoRenewOff} (renewal, the DNS credentials automatic renewal requires, or
     * the CA) is off:
     * <ul>
     *   <li>only renewal or DNS credentials off: enabled and held as the renewal trigger holds, due again later,
     *       so it resumes by itself once they are back on, even in an organization the lifecycle never paused;</li>
     *   <li>the CA off as well: left disabled, and held for CERTIFICATE_RENEWAL's lifecycle when renewal or DNS
     *       credentials are off;</li>
     *   <li>only the CA off: left disabled.</li>
     * </ul>
     *
     * @return whether automatic renewal runs for the certificate now
     */
    private boolean enableIssuedSchedule(CertificateEntity cert, CertIssuanceResponse response,
                                         List<String> autoRenewOff) {
        boolean autoRenew = autoRenewOff.isEmpty();
        List<String> renewalKeys = FeatureFlags.automaticWorkKeys(FeatureFlags.CERTIFICATE_RENEWAL);
        boolean heldByTrigger = !autoRenew && renewalKeys.containsAll(autoRenewOff);
        String holdStatus = autoRenewOff.stream().anyMatch(renewalKeys::contains)
                ? RenewalStatus.FEATURE_HOLD.name()
                : null;
        String xref = cert.getCertificateXref();
        Optional<RenewalScheduleEntity> scheduleOpt = renewalScheduleRepository.findByCertificateXref(xref);
        if (scheduleOpt.isEmpty()) {
            log.error("No renewal schedule found for xref={} after issuance — creating recovery schedule", xref);
            return createRecoverySchedule(cert, loadCredConfigForCert(cert), false, autoRenew, holdStatus);
        }
        RenewalScheduleEntity rs = scheduleOpt.get();
        if (autoRenew || heldByTrigger) {
            rs.setEnabled(true);
        }
        if (heldByTrigger) {
            rs.setNextAttemptAt(RenewalRetryPolicy.holdRecheckAt());
        }
        rs.setLastRenewalStatus(holdStatus);
        copyIssuedHandles(rs, response);
        if (cert.getValidTo() != null) {
            rs.setValidTo(cert.getValidTo());
            rs.setRenewalEligibleAt(RenewalTiming.eligibleAt(cert.getValidFrom(), cert.getValidTo(), rs.getRenewalWindowDays()));
        }
        renewalScheduleRepository.save(rs);
        return autoRenew;
    }

    private static void copyIssuedHandles(RenewalScheduleEntity rs, CertIssuanceResponse response) {
        if (response.getAcmeAccountHandle() != null) {
            rs.setAcmeAccountHandle(response.getAcmeAccountHandle());
        }
        if (response.getOrderId() != null && !response.getOrderId().isBlank()) {
            rs.setOrderId(response.getOrderId());
        }
        if (response.getCertSecretHandle() != null && !response.getCertSecretHandle().isBlank()) {
            rs.setCertSecretHandle(response.getCertSecretHandle());
        }
    }

    private NotifPayload handleRenewalSuccess(CertIssuanceResponse response, VerifiedAgentMessage verified) {
        log.info("CERT_ISSUANCE_RESPONSE (RENEWED): xref={}", response.getCertificateXref());
        try (AuditScope scope = agentScope(response.getOrganizationId(), verified, response.getCorrelationId())) {
            SuccessOutcome outcome = transactionTemplate.execute(status -> applyRenewal(response, verified));
            return completeAfterCommit(outcome, verified);
        }
    }

    private SuccessOutcome applyRenewal(CertIssuanceResponse response, VerifiedAgentMessage verified) {
        AutoRenewFeatureLocks locks = lockAutoRenewFeatures(response, verified);
        String renewedXref = response.getCertificateXref();
        Optional<CertificateEntity> renewedOpt = findCertificateForOrganization(renewedXref, verified);
        if (renewedOpt.isEmpty()) {
            log.error("Renewed certificate draft not found for xref={} — ignoring response", renewedXref);
            return SuccessOutcome.NOTHING;
        }
        CertificateEntity renewedCert = renewedOpt.get();
        Long organizationId = renewedCert.getOrganizationId();
        CaProvider caProvider = response.getCaProvider() != null ? response.getCaProvider() : renewedCert.getCaProvider();
        holdCertificateLocks(locks, organizationId, caProvider);
        if (AbandonedRenewalCleanup.endedByTimeout(renewedCert)) {
            // The attempt was ended after its horizon and the schedule has moved on; pairing this result with
            // whatever renews now would attach it to another attempt. The CA-issued certificate is left unused.
            log.error("[RENEWAL_RESULT_AFTER_TIMEOUT] xref={} org={} ca={} serial={} orderId={} caOrderAction={}: "
                            + "the result arrived after the attempt was ended and is not applied",
                    renewedXref, organizationId, caProvider, response.getSerialNumber(), response.getOrderId(),
                    response.getCaOrderAction());
            Metrics.counter(AbandonedRenewalCleanup.RESULT_AFTER_TIMEOUT_METRIC, "kind", "renewal").increment();
            return SuccessOutcome.NOTHING;
        }
        if (isRenewalAlreadyApplied(renewedCert, response)) {
            log.info("Duplicate renewal success for requestId={}, xref={} — replaying the post-commit work only",
                    response.getRequestId(), renewedXref);
            CertificateEntity replaced = certificateRepository
                    .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                            renewedCert.getUserDomainCertId(), CertificateStatus.RENEW_SUCCESS.name())
                    .orElse(null);
            return replayOutcome(renewedCert, response, organizationId, true,
                    renewalSuccessNotification(renewedCert, replaced, response),
                    renewedNotDeployedNotification(renewedCert, replaced, response));
        }

        CertificateEntity previousCert = certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                        renewedCert.getUserDomainCertId(), CertificateStatus.RENEWING.name())
                .orElse(null);
        if (previousCert == null) {
            log.error("Previous renewing certificate not found for renewed xref={} — ignoring response", renewedXref);
            return SuccessOutcome.NOTHING;
        }
        String previousXref = previousCert.getCertificateXref();
        String prevStatus = previousCert.getStatus();

        if (response.getCaProvider() != null) {
            renewedCert.setCaProvider(response.getCaProvider());
        }
        applyIssuedFields(renewedCert, response);

        previousCert.setStatus(CertificateStatus.RENEW_SUCCESS.name());
        previousCert.setLastErrorCode(null);
        previousCert.setLastErrorMessage(null);
        previousCert.setLastErrorAt(null);
        certificateRepository.save(previousCert);
        certificateRepository.save(renewedCert);

        upsertCryptoMetadata(renewedXref, response);

        List<String> autoRenewOff = autoRenewFeaturesOff(organizationId, caProvider);
        boolean scheduleEnabled = moveScheduleToRenewed(previousCert, renewedCert, response, autoRenewOff.isEmpty());

        if (insertEvent(previousXref, previousCert.getOrganizationId(), CertEventType.RENEWAL_SUCCESS.name(), prevStatus,
                CertificateStatus.RENEW_SUCCESS.name(),
                response.getRequestId(), response.getCorrelationId(), EventSource.AGENT.value(),
                Map.of("domain", orEmpty(previousCert.getDomain()),
                        "validTo", orEmpty(response.getValidTo()),
                        "renewedCertificateXref", renewedXref))) {
            certificateAudit.renewed(renewedCert, previousXref, requestedBy(response.getRequestId()));
        }
        recordAutoRenewSkipped(renewedCert, response, autoRenewOff, scheduleEnabled, FLOW_POST_RENEWAL);

        NotifPayload notification = renewalSuccessNotification(renewedCert, previousCert, response);
        NotifPayload notDeployed = renewedNotDeployedNotification(renewedCert, previousCert, response);
        DeployDecision deploy = decideDeploy(renewedCert, response, organizationId, true, false);
        if (deploy.skippedFeatureOff()) {
            recordAutoDeploySkipped(renewedCert, response.getRequestId(), response.getCorrelationId(), FLOW_POST_RENEWAL);
            // Renewals run unattended: tell the customer the new cert is not live on their targets.
            notification = notification.withFollowUp(notDeployed);
        }
        return new SuccessOutcome(true, true, renewedXref, response.getRequestId(), response.getCorrelationId(),
                deploy.intent(), notification, notDeployed);
    }

    /**
     * Moves the renewal schedule from the replaced certificate to the renewed one and records the
     * renewal; automatic renewal is (re-)enabled only when {@code autoRenew} is true, otherwise the
     * schedule keeps its enabled state (an org admin's DISABLE_AUTO_RENEW stays in force).
     *
     * @return whether the schedule ends up enabled
     */
    private boolean moveScheduleToRenewed(CertificateEntity previousCert, CertificateEntity renewedCert,
                                          CertIssuanceResponse response, boolean autoRenew) {
        Optional<RenewalScheduleEntity> scheduleOpt =
                renewalScheduleRepository.findByCertificateXref(previousCert.getCertificateXref());
        if (scheduleOpt.isEmpty()) {
            scheduleOpt = renewalScheduleRepository.findByCertificateXref(renewedCert.getCertificateXref());
        }
        if (scheduleOpt.isEmpty()) {
            log.error("No renewal schedule found for xref={} after renewal — creating recovery schedule",
                    previousCert.getCertificateXref());
            return createRecoverySchedule(renewedCert, loadCredConfigForCert(previousCert), true, autoRenew, null);
        }
        RenewalScheduleEntity rs = scheduleOpt.get();
        boolean held = rs.heldByFeatureSwitch();
        rs.setCertificateXref(renewedCert.getCertificateXref());
        if (autoRenew && !held) {
            rs.setEnabled(true);
        }
        rs.setLastRenewalAt(OffsetDateTime.now(ZoneOffset.UTC));
        if (!held) {
            rs.setLastRenewalStatus(RenewalStatus.SUCCESS.name());
        }
        rs.setNextAttemptAt(null);
        rs.setConsecutiveFailures(0);
        copyIssuedHandles(rs, response);
        if (renewedCert.getValidTo() != null) {
            rs.setValidTo(renewedCert.getValidTo());
            rs.setRenewalEligibleAt(RenewalTiming.eligibleAt(renewedCert.getValidFrom(), renewedCert.getValidTo(), rs.getRenewalWindowDays()));
        }
        renewalScheduleRepository.save(rs);
        return Boolean.TRUE.equals(rs.getEnabled());
    }

    /**
     * The first statements of a success transaction: the CERTIFICATE_RENEWAL and CA locks of the
     * organization the message is for, before any read. A message that names no organization is
     * locked once its certificate is read ({@link #holdCertificateLocks}).
     */
    private AutoRenewFeatureLocks lockAutoRenewFeatures(CertIssuanceResponse response, VerifiedAgentMessage verified) {
        AutoRenewFeatureLocks locks = new AutoRenewFeatureLocks(featureLifecycleLock);
        Long organizationId = organizationOf(response.getOrganizationId(), verified);
        if (organizationId != null) {
            locks.acquire(organizationId, AutoRenewFeatureLocks.featureKeysFor(response.getCaProvider()));
        }
        return locks;
    }

    private static void holdCertificateLocks(AutoRenewFeatureLocks locks, Long organizationId, CaProvider caProvider) {
        if (organizationId != null) {
            locks.ensureHeld(organizationId, caProvider);
        }
    }

    /**
     * The flags, read past the cache under their locks, that keep automatic renewal off for a
     * certificate of {@code caProvider}: renewal itself and the CA. Empty when it may renew.
     */
    private List<String> autoRenewFeaturesOff(Long organizationId, CaProvider caProvider) {
        List<String> off = new ArrayList<>();
        featureFlagResolver.automaticWorkBlockerUncached(FeatureFlags.CERTIFICATE_RENEWAL, organizationId)
                .ifPresent(off::add);
        if (caProvider != null) {
            String caFeatureKey = CertIssuanceService.toCaFeatureKey(caProvider);
            if (!featureFlagResolver.resolveUncached(caFeatureKey, organizationId)) {
                off.add(caFeatureKey);
            }
        }
        return off;
    }

    /**
     * Whether an earlier delivery already applied this issuance: the certificate is ACTIVE with the
     * serial (and secret handle) the response reports, or, for a response without a serial, its
     * ISSUANCE_SUCCESS event is recorded.
     */
    private boolean isIssuanceAlreadyApplied(CertificateEntity cert, CertIssuanceResponse response) {
        if (!CertificateStatus.ACTIVE.name().equals(cert.getStatus())) {
            return false;
        }
        return isBlank(response.getSerialNumber())
                ? isSuccessRecorded(response, CertEventType.ISSUANCE_SUCCESS)
                : holdsIssuedCertificate(cert, response);
    }

    /** {@link #isIssuanceAlreadyApplied} for a renewal; its RENEWAL_SUCCESS event also proves it. */
    private boolean isRenewalAlreadyApplied(CertificateEntity renewedCert, CertIssuanceResponse response) {
        return isSuccessRecorded(response, CertEventType.RENEWAL_SUCCESS)
                || (CertificateStatus.ACTIVE.name().equals(renewedCert.getStatus())
                        && !isBlank(response.getSerialNumber())
                        && holdsIssuedCertificate(renewedCert, response));
    }

    private boolean isSuccessRecorded(CertIssuanceResponse response, CertEventType eventType) {
        return response.getRequestId() != null
                && eventRepository.existsByRequestIdAndEventType(response.getRequestId(), eventType.name());
    }

    private static boolean holdsIssuedCertificate(CertificateEntity cert, CertIssuanceResponse response) {
        return response.getSerialNumber().equalsIgnoreCase(cert.getSerialNumber())
                && (isBlank(response.getCertSecretHandle())
                        || response.getCertSecretHandle().equals(cert.getCertSecretHandle()));
    }

    /**
     * The outcome of a redelivery whose response was already applied: nothing is written; the deploy
     * is dispatched again only when no deployment was recorded for the certificate and flow, and the
     * notifications are published again under their deterministic request ids.
     */
    private SuccessOutcome replayOutcome(CertificateEntity cert, CertIssuanceResponse response, Long organizationId,
                                         boolean renewal, NotifPayload notification, NotifPayload notDeployed) {
        DeployDecision deploy = decideDeploy(cert, response, organizationId, renewal, true);
        NotifPayload toPublish = deploy.skippedFeatureOff() && notDeployed != null
                ? notification.withFollowUp(notDeployed) : notification;
        return new SuccessOutcome(false, renewal, cert.getCertificateXref(), response.getRequestId(),
                response.getCorrelationId(), deploy.intent(), toPublish, notDeployed);
    }

    /**
     * Decides, inside the transaction, what the automatic deploy after this success does, reading
     * {@code CERTIFICATE_DEPLOYMENT} past the cache. On a redelivery a deployment already recorded
     * for the certificate and flow means it went out: nothing is dispatched or reported again.
     */
    private DeployDecision decideDeploy(CertificateEntity cert, CertIssuanceResponse response, Long organizationId,
                                        boolean renewal, boolean redelivery) {
        boolean akamai = AkamaiSpecialIssuanceService.AKAMAI_CPS.equals(cert.getSpecialCertificateType());
        String flowType = akamai ? FLOW_POST_AKAMAI_ISSUANCE : renewal ? FLOW_POST_RENEWAL : FLOW_POST_ISSUANCE;
        if (redelivery && deploymentRepository.existsByCertificateXrefAndFlowType(cert.getCertificateXref(), flowType)) {
            log.info("Automatic deploy of xref={} ({}) already went out — not dispatching it again",
                    cert.getCertificateXref(), flowType);
            return DeployDecision.NONE;
        }
        boolean deploymentEnabled =
                featureFlagResolver.resolveUncached(FeatureFlags.CERTIFICATE_DEPLOYMENT, organizationId);
        DeploymentExecutionService.AutoDeployOutcome planned = akamai
                ? planAkamaiDeploy(cert, deploymentEnabled)
                : deploymentExecutionService.planAutoDeploy(cert, deploymentEnabled);
        if (planned == DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF) {
            return DeployDecision.SKIPPED_FEATURE_OFF;
        }
        if (planned != DeploymentExecutionService.AutoDeployOutcome.DISPATCHED) {
            return DeployDecision.NONE;
        }
        // A renewal deploys the renewed cert's stored handle; an issuance the one the agent reported.
        String certSecretHandle = renewal ? cert.getCertSecretHandle() : response.getCertSecretHandle();
        return new DeployDecision(
                new DeployIntent(certSecretHandle, response.getOrganizationId(), flowType, akamai), false);
    }

    /**
     * After the success transaction committed: dispatches the decided deploy and
     * returns the notifications for process() to publish. Runs with no transaction open.
     */
    private NotifPayload completeAfterCommit(SuccessOutcome outcome, VerifiedAgentMessage verified) {
        if (outcome == null || outcome.certificateXref() == null) {
            return null;
        }
        Optional<CertificateEntity> committed = findCertificateForOrganization(outcome.certificateXref(), verified);
        if (committed.isEmpty()) {
            log.warn("Certificate xref={} disappeared after its success committed — nothing to deploy",
                    outcome.certificateXref());
            return outcome.notification();
        }
        CertificateEntity cert = committed.get();
        if (outcome.deploy() == null
                || dispatch(cert, outcome.deploy()) != DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF) {
            return outcome.notification();
        }
        // CERTIFICATE_DEPLOYMENT went off between the commit and the dispatch. No transaction is open here: the
        // timeline event and its audit row get one of their own.
        if (outcome.transitioned()) {
            transactionTemplate.executeWithoutResult(status -> recordAutoDeploySkipped(cert, outcome.requestId(),
                    outcome.correlationId(), outcome.renewal() ? FLOW_POST_RENEWAL : FLOW_POST_ISSUANCE));
        }
        return outcome.notification().withFollowUp(outcome.notDeployed());
    }

    private DeploymentExecutionService.AutoDeployOutcome dispatch(CertificateEntity cert, DeployIntent intent) {
        if (intent.akamai()) {
            return dispatchAkamaiSpecialCert(cert, intent.certSecretHandle(), intent.organizationId());
        }
        return deploymentExecutionService.dispatchForCert(
                cert, intent.certSecretHandle(), intent.organizationId(), intent.flowType());
    }

    private NotifPayload issuanceSuccessNotification(CertificateEntity cert, CertIssuanceResponse response) {
        return new NotifPayload("CERT_ISSUANCE_SUCCESS", response.getOrganizationId(), cert.getCertificateXref(),
                Map.of("domain", orEmpty(cert.getDomain()),
                       "validFrom", orEmpty(response.getValidFrom()),
                       "validTo", orEmpty(response.getValidTo()),
                       "requestId", successRequestId(response, cert.getCertificateXref(), "ISSUED")));
    }

    private NotifPayload renewalSuccessNotification(CertificateEntity renewedCert, CertificateEntity previousCert,
                                                    CertIssuanceResponse response) {
        return new NotifPayload("CERT_RENEWAL_SUCCESS", response.getOrganizationId(), renewedCert.getCertificateXref(),
                Map.of("domain", orEmpty(renewedCert.getDomain()),
                        "validFrom", orEmpty(response.getValidFrom()),
                        "validTo", orEmpty(response.getValidTo()),
                        "requestId", successRequestId(response, renewedCert.getCertificateXref(), "RENEWED"),
                        "previousCertificateXref", previousCert == null ? "" : orEmpty(previousCert.getCertificateXref())));
    }

    /**
     * Tells the customer a renewed certificate was not deployed because deployment is off.
     * previousValidTo: the certificate still installed on the targets expires then.
     */
    private NotifPayload renewedNotDeployedNotification(CertificateEntity renewedCert, CertificateEntity previousCert,
                                                        CertIssuanceResponse response) {
        String renewedXref = renewedCert.getCertificateXref();
        return new NotifPayload(CERT_RENEWED_NOT_DEPLOYED, response.getOrganizationId(), renewedXref,
                Map.of("domain", orEmpty(renewedCert.getDomain()),
                        "validTo", orEmpty(response.getValidTo()),
                        "previousValidTo", previousCert != null && previousCert.getValidTo() != null
                                ? previousCert.getValidTo().toString() : "",
                        "reason", "CERTIFICATE_DEPLOYMENT_DISABLED",
                        "previousCertificateXref", previousCert == null ? "" : orEmpty(previousCert.getCertificateXref()),
                        "requestId", notDeployedRequestId(response, renewedXref)));
    }

    /**
     * The notifier's deliver-once key for a success email: the response's request id (as before), or,
     * when it has none, one derived from the certificate, the serial (or secret handle) the CA issued
     * and the kind, so every redelivery of the same response maps to the same email.
     */
    static String successRequestId(CertIssuanceResponse response, String certificateXref, String kind) {
        if (!isBlank(response.getRequestId())) {
            return response.getRequestId();
        }
        return certificateXref + ":" + firstNonBlank(response.getSerialNumber(), response.getCertSecretHandle()) + ":" + kind;
    }

    /**
     * The notifier's natural key for the "renewed, not deployed" email: derived from the renewal
     * response, so a redelivered or reprocessed response maps to the same email instead of a second
     * one. Falls back to the correlation id, then the renewed certificate.
     */
    static String notDeployedRequestId(CertIssuanceResponse response, String renewedXref) {
        String base = firstNonBlank(response.getRequestId(), response.getCorrelationId(), renewedXref);
        return base + ":not-deployed";
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return "";
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Makes a skipped auto-deploy visible on the certificate's timeline and in the audit trail. Call it in a
     * transaction: the audit row is written in it.
     */
    private void recordAutoDeploySkipped(CertificateEntity cert, String requestId, String correlationId,
                                         String flowType) {
        if (insertEvent(cert.getCertificateXref(), cert.getOrganizationId(),
                CertEventType.AUTO_DEPLOY_SKIPPED_FEATURE_OFF.name(), cert.getStatus(), cert.getStatus(),
                requestId, correlationId, EventSource.CERT_MANAGER.value(),
                Map.of("flowType", flowType, "featureKey", FeatureFlags.CERTIFICATE_DEPLOYMENT))) {
            certificateAudit.autoDeploySkipped(cert, flowType);
        }
    }

    /** Makes automatic renewal left off visible on the certificate's timeline. */
    private void recordAutoRenewSkipped(CertificateEntity cert, CertIssuanceResponse response, List<String> featuresOff,
                                        boolean scheduleEnabled, String flowType) {
        if (featuresOff.isEmpty() || scheduleEnabled) {
            return;
        }
        log.info("Automatic renewal left off for xref={}: {} off for org={}",
                cert.getCertificateXref(), featuresOff, cert.getOrganizationId());
        if (insertEvent(cert.getCertificateXref(), cert.getOrganizationId(),
                CertEventType.AUTO_RENEW_SKIPPED_FEATURE_OFF.name(), cert.getStatus(), cert.getStatus(),
                response.getRequestId(), response.getCorrelationId(), EventSource.CERT_MANAGER.value(),
                Map.of("flowType", flowType, "featureKeys", featuresOff))) {
            certificateAudit.autoRenewalSkipped(cert, featuresOff, flowType);
        }
    }

    private NotifPayload handleDeploymentSuccess(CertDeploymentResponse response, VerifiedAgentMessage verified) {
        try (AuditScope scope = agentScope(response.getOrganizationId(), verified, response.getCorrelationId())) {
            return applyDeploymentResponse(response, verified);
        }
    }

    private NotifPayload applyDeploymentResponse(CertDeploymentResponse response, VerifiedAgentMessage verified) {
        String xref = response.getCertificateXref();
        log.info("CERT_DEPLOYMENT_RESPONSE: xref={}, targetType={}, targetResourceId={}",
                xref, response.getTargetType(), response.getTargetResourceId());

        Optional<CertificateEntity> optCert = findCertificateForOrganization(xref, verified);
        if (optCert.isEmpty()) {
            log.error("Certificate not found for xref={} — cert may have been deleted between " +
                      "deployment dispatch and agent response. Ignoring.", xref);
            return null;
        }
        CertificateEntity cert = optCert.get();
        final String fromStatus = cert.getStatus();

        if (response.getTargetResourceId() == null || response.getTargetResourceId().isBlank()) {
            log.error("Deployment response for xref={} has status=SUCCESS but targetResourceId is " +
                      "null/empty — recording deployment failure only", xref);

            // The response itself is malformed: the agent's defect, not the customer's. No transaction is open
            // here, so the timeline event and its audit row get one of their own.
            transactionTemplate.executeWithoutResult(status -> {
                if (insertEvent(xref, cert.getOrganizationId(), CertEventType.DEPLOYMENT_FAILED.name(), fromStatus,
                        fromStatus, response.getRequestId(), response.getCorrelationId(), EventSource.AGENT.value(),
                        Map.of("errorCode", "INVALID_DEPLOYMENT_RESPONSE",
                               "errorDetail", "targetResourceId was null/empty in agent SUCCESS response",
                               "targetType", nameOf(response.getTargetType())))) {
                    certificateAudit.deploymentFailed(cert, nameOf(response.getTargetType()), null,
                            AuditReason.INTERNAL_ERROR, requestedBy(response.getRequestId()));
                }
            });

                deploymentExecutionService.handleAgentFailure(
                    response.getRequestId(),
                    organizationOf(response.getOrganizationId(), verified),
                    "INVALID_DEPLOYMENT_RESPONSE",
                    "targetResourceId was null/empty in agent SUCCESS response",
                    parseDateTime(response.getRespondedAt()));

            saveFailureAlert(cert, "CERT_DEPLOYMENT", "INVALID_DEPLOYMENT_RESPONSE",
                    "Agent returned SUCCESS but targetResourceId was null/empty", null, null);

            return new NotifPayload("CERT_DEPLOYMENT_FAILED", response.getOrganizationId(), xref,
                    Map.of("errorCode", "INVALID_DEPLOYMENT_RESPONSE",
                       "domain", orEmpty(cert.getDomain()),
                       "requestId", orEmpty(response.getRequestId())));
        }

        String resourceIdFormatError = validateTargetResourceIdFormat(
                response.getTargetResourceId(), response.getTargetType());
        if (resourceIdFormatError != null) {
            log.error("Deployment response for xref={} has malformed targetResourceId: {}", xref, resourceIdFormatError);
            transactionTemplate.executeWithoutResult(status -> {
                if (insertEvent(xref, cert.getOrganizationId(), CertEventType.DEPLOYMENT_FAILED.name(), fromStatus,
                        fromStatus, response.getRequestId(), response.getCorrelationId(), EventSource.AGENT.value(),
                        Map.of("errorCode", "INVALID_RESOURCE_ID_FORMAT",
                               "errorDetail", resourceIdFormatError,
                               "targetType", nameOf(response.getTargetType())))) {
                    certificateAudit.deploymentFailed(cert, nameOf(response.getTargetType()), null,
                            AuditReason.INTERNAL_ERROR, requestedBy(response.getRequestId()));
                }
            });

                deploymentExecutionService.handleAgentFailure(
                    response.getRequestId(),
                    organizationOf(response.getOrganizationId(), verified),
                    "INVALID_RESOURCE_ID_FORMAT",
                    resourceIdFormatError,
                    parseDateTime(response.getRespondedAt()));

            saveFailureAlert(cert, "CERT_DEPLOYMENT", "INVALID_RESOURCE_ID_FORMAT", resourceIdFormatError, null, null);

            return new NotifPayload("CERT_DEPLOYMENT_FAILED", response.getOrganizationId(), xref,
                    Map.of("errorCode", "INVALID_RESOURCE_ID_FORMAT",
                       "domain", orEmpty(cert.getDomain()),
                       "requestId", orEmpty(response.getRequestId())));
        }

        deploymentExecutionService.handleAgentSuccess(
            response.getRequestId(),
            organizationOf(response.getOrganizationId(), verified),
            response.getTargetResourceId(),
            parseDateTime(response.getRespondedAt()));

        // Persist the per-certificate config returned by the agent on first deployments.
        // On subsequent deployments configJson is null — no action needed.
        if (response.getConfigJson() != null && !response.getConfigJson().isBlank()
                && cert.getUserDomainCertId() != null
                && response.getTargetType() != null) {
            deploymentExecutionService.findDeployment(response.getRequestId(),
                    organizationOf(response.getOrganizationId(), verified)).ifPresent(deployment -> {
                if (deployment.getDeploymentCredentialXref() != null) {
                    certDeploymentConfigService.mergeDeploymentResultFromAgent(
                            cert.getOrganizationId(),
                            cert.getUserDomainCertId(),
                            deployment.getDeploymentCredentialXref(),
                            nameOf(response.getTargetType()),
                            response.getConfigJson());
                }
            });
        }

        // The timeline event and its audit row in one transaction of their own: this handler runs with none.
        transactionTemplate.executeWithoutResult(status -> {
            if (insertEvent(xref, cert.getOrganizationId(), CertEventType.DEPLOYMENT_SUCCESS.name(), fromStatus,
                    fromStatus, response.getRequestId(), response.getCorrelationId(), EventSource.AGENT.value(),
                    Map.of("targetType", nameOf(response.getTargetType()),
                           "targetResourceId", orEmpty(response.getTargetResourceId())))) {
                certificateAudit.deploymentSucceeded(cert, nameOf(response.getTargetType()), null,
                        requestedBy(response.getRequestId()));
            }
        });

        return new NotifPayload("CERT_DEPLOYMENT_SUCCESS", response.getOrganizationId(), xref,
                Map.of("domain", orEmpty(cert.getDomain()),
                       "targetType", nameOf(response.getTargetType()),
                       "result", orEmpty(response.getStatus()),
                   "respondedAt", orEmpty(response.getRespondedAt()),
                   "requestId", orEmpty(response.getRequestId())));
    }

    private NotifPayload handleRevocationResponse(CertRevocationResponse response, VerifiedAgentMessage verified) {
        try (AuditScope scope = agentScope(response.getOrganizationId(), verified, response.getCorrelationId())) {
            return applyRevocationResponse(response, verified);
        }
    }

    private NotifPayload applyRevocationResponse(CertRevocationResponse response, VerifiedAgentMessage verified) {
        String xref = response.getCertificateXref();
        log.info("[handleRevocationResponse] cert={}, ca={}",
            xref, response.getCaProvider());

        Optional<CertificateEntity> optCert = findCertificateForOrganization(xref, verified);
        if (optCert.isEmpty()) {
            log.error("[handleRevocationResponse] cert not found: {} — ignoring", xref);
            return null;
        }
        CertificateEntity cert = optCert.get();

        if (response.getOrganizationId() != null
                && !response.getOrganizationId().equalsIgnoreCase(cert.getOrganizationId().toString())) {
            log.error("[handleRevocationResponse] organizationId mismatch for xref={}: message={}, cert={}",
                    xref, response.getOrganizationId(), cert.getOrganizationId());
            return null;
        }

        if (CertificateStatus.REVOKED.name().equals(cert.getStatus())) {
            log.info("[handleRevocationResponse] cert={} already REVOKED — idempotent skip", xref);
            return null;
        }
        if (!CertificateStatus.REVOKING.name().equals(cert.getStatus())) {
            log.warn("[handleRevocationResponse] cert={} expected REVOKING but was {} — ignoring",
                    xref, cert.getStatus());
            return null;
        }

        String prevStatus = cert.getStatus();

        // The revocation, its timeline event and its audit row in one transaction: this handler runs with none.
        transactionTemplate.executeWithoutResult(status -> {
            cert.setStatus(CertificateStatus.REVOKED.name());
            cert.setLastErrorCode(null);
            cert.setLastErrorMessage(null);
            cert.setLastErrorAt(null);
            cert.setUpdatedAt(OffsetDateTime.now(ZoneOffset.UTC));
            certificateRepository.save(cert);

            if (insertEvent(xref, cert.getOrganizationId(),
                    CertEventType.REVOCATION_SUCCESS.name(), prevStatus, CertificateStatus.REVOKED.name(),
                    response.getRequestId(), response.getCorrelationId(), EventSource.AGENT.value(),
                    Map.of("caProvider", response.getCaProvider() != null ? response.getCaProvider().name() : "",
                       "revocationReason", orEmpty(response.getRevocationReason())))) {
                certificateAudit.revoked(cert, requestedBy(response.getRequestId()), response.getRevocationReason());
            }
        });

        String reasonForNotif = response.getRevocationReason() != null
            ? response.getRevocationReason()
            : ErrorCodes.DEFAULT_REVOCATION_REASON;

        String organizationIdStr = cert.getOrganizationId().toString();

        // Lightweight post-revocation cleanup: disable the renewal_schedule so the
        // cron doesn't try to renew a REVOKED cert. The cert itself stays visible in REVOKED status (list/history
        // GET endpoints continue to return it) so the user can delete it explicitly
        // when ready — the cert-delete + UDC-delete endpoints handle cascade.
        // Let exceptions propagate so the message is abandoned + retried on failure.
        certIssuanceService.finalizeRevocation(cert.getOrganizationId(), xref);

        return new NotifPayload("CERT_REVOKED",
                organizationIdStr, xref,
                Map.of("domain", orEmpty(cert.getDomain()),
                   "reason", reasonForNotif,
                   "requestId", orEmpty(response.getRequestId())));
    }

    private void handleKvDeleteResponse(CertSecretDeleteResponse response) {
        if ("SUCCESS".equalsIgnoreCase(response.getStatus())) {
            log.info("[handleKvDeleteResponse] KV secret deleted successfully: xref={}, organizationId={}",
                    response.getCertificateXref(), response.getOrganizationId());
        } else {
            log.warn("[handleKvDeleteResponse] KV secret deletion reported failure: xref={}, organizationId={}, errorCode={}, detail={}",
                    response.getCertificateXref(), response.getOrganizationId(),
                    response.getErrorCode(), response.getErrorDetail());
        }
    }

    private NotifPayload handleAgentError(AgentErrorMessage error, VerifiedAgentMessage verified) {
        String xref = error.getCertificateXref();
        log.warn("AGENT_ERROR: originalMessageType={}, xref={}, code={}",
                error.getOriginalMessageType(), xref, error.getErrorCode());

        if ("DEVICE_IDENTITY_SYNC_COMMAND".equals(error.getOriginalMessageType())) {
            Long orgId = organizationOf(error.getOrganizationId(), verified);
            iotIdentitySyncResponseHandler.handleAgentError(
                    error.getSourceXref(), orgId, error.getSyncXref(),
                    error.getErrorCode(), error.getErrorDetail());
            return null;
        }

        if ("IOT_CERTIFICATE_REVOCATION_COMMAND".equals(error.getOriginalMessageType())) {
            iotRevocationResultService.handleAgentError(error);
            return null;
        }

        if ("IOT_INTUNE_REVOCATION_POLL_COMMAND".equals(error.getOriginalMessageType())) {
            iotIntuneRevocationWorkflow.handleAgentError(error, false);
            return null;
        }

        if ("IOT_INTUNE_REVOCATION_UPLOAD_COMMAND".equals(error.getOriginalMessageType())) {
            iotIntuneRevocationWorkflow.handleAgentError(error, true);
            return null;
        }

        if ("IOT_CERTIFICATE_PROFILE_COMMAND".equals(error.getOriginalMessageType())) {
            certificateProfileResponseHandler.handleOperationAgentError(
                    error.getSourceXref(), organizationOf(error.getOrganizationId(), verified),
                    error.getRequestId(), error.getErrorCode(), error.getErrorDetail(),
                    error.getRespondedAt());
            return null;
        }

        if ("IOT_CERTIFICATE_PROFILE_SYNC_COMMAND".equals(error.getOriginalMessageType())) {
            certificateProfileResponseHandler.handleSyncAgentError(
                    error.getSourceXref(), organizationOf(error.getOrganizationId(), verified),
                    error.getRequestId(), error.getErrorCode(), error.getErrorDetail(),
                    error.getRespondedAt());
            return null;
        }

        if ("CERT_DISCOVERY".equals(error.getOriginalMessageType())) {
            if (error.getRequestId() == null || error.getRequestId().isBlank()) {
                log.warn("Ignoring discovery AGENT_ERROR without requestId: code={}", error.getErrorCode());
                return null;
            }
            discoveryService.markDiscoveryAgentFailed(
                    error.getRequestId(), organizationOf(error.getOrganizationId(), verified),
                    error.getErrorCode(), error.getErrorDetail());
            return null;
        }

        try (AuditScope scope = agentScope(error.getOrganizationId(), verified, error.getCorrelationId())) {
            return applyCertificateAgentError(error, verified, xref);
        }
    }

    /** {@link #handleAgentError} for a certificate command: issuance, renewal, deployment or revocation. */
    private NotifPayload applyCertificateAgentError(AgentErrorMessage error, VerifiedAgentMessage verified,
                                                    String xref) {
        String derivedEventType = deriveEventType(error.getOriginalMessageType());
        if (error.getRequestId() != null
            && eventRepository.existsByRequestIdAndEventType(error.getRequestId(), derivedEventType)) {
            log.info("Duplicate AGENT_ERROR suppressed for requestId={}, eventType={}, xref={}",
                error.getRequestId(), derivedEventType, xref);
            return null;
        }

        Optional<CertificateEntity> optCert = findCertificateForOrganization(xref, verified);
        if (optCert.isEmpty()) {
            log.error("Certificate not found for xref={} — ignoring AGENT_ERROR response", xref);
            return null;
        }
        CertificateEntity cert = optCert.get();
        String staleReason = staleFailureReason(error, cert, verified);
        if (staleReason != null) {
            log.info("Ignoring stale AGENT_ERROR for xref={}, type={}, requestId={}, errorCode={}: {}",
                    xref, error.getOriginalMessageType(), error.getRequestId(), error.getErrorCode(), staleReason);
            return null;
        }
        String prevStatus = cert.getStatus();
        String notifAction = determineFailureAction(error.getOriginalMessageType());
        OffsetDateTime errorAt = OffsetDateTime.now(ZoneOffset.UTC);

        if (isIssuanceFailureType(error.getOriginalMessageType())) {
            cert.setStatus(CertificateStatus.FAILED.name());
            applyCertFailure(cert, error, errorAt);
            certificateRepository.save(cert);
        }

        if ("CERT_RENEWAL".equals(error.getOriginalMessageType())) {
            Optional<RenewalScheduleEntity> scheduleOpt = renewalScheduleRepository.findByCertificateXref(xref);
            if (scheduleOpt.isEmpty()) {
                scheduleOpt = findCertificateForOrganization(xref, verified)
                        .flatMap(c -> certificateRepository
                                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                                        c.getUserDomainCertId(), CertificateStatus.RENEWING.name()))
                        .flatMap(prev -> renewalScheduleRepository.findByCertificateXref(prev.getCertificateXref()));
            }
            scheduleOpt.ifPresent(rs -> {
                RenewalRetryPolicy.recordFailure(rs);
                renewalScheduleRepository.save(rs);
            });

            // Renewal commands now run against a pre-created draft certificate.
            // Persist that draft as RENEWAL_FAILED so it is auditable but list-filtered.
            if (CertificateStatus.PENDING.name().equals(cert.getStatus())) {
                cert.setStatus(CertificateStatus.RENEWAL_FAILED.name());
                applyCertFailure(cert, error, errorAt);
                certificateRepository.save(cert);
            }

            resolveRenewingCertForFailure(cert).ifPresent(previous -> {
                previous.setStatus(derivePostRenewalFailureStatus(previous));
                applyCertFailure(previous, error, errorAt);
                certificateRepository.save(previous);
            });
        }

        if ("CERT_REVOCATION_COMMAND".equals(error.getOriginalMessageType())
                && CertificateStatus.REVOKING.name().equals(cert.getStatus())) {
            cert.setStatus(CertificateStatus.REVOCATION_FAILED.name());
            applyCertFailure(cert, error, errorAt);
            certificateRepository.save(cert);
        }

        if ("CERT_DEPLOYMENT".equals(error.getOriginalMessageType())) {
            // RETRY_GIVE_UP wraps an inner classifier in lastReason; persist the unwrapped code so
            // the deployment's user-facing message reflects the real cause, not the retry wrapper.
            deploymentExecutionService.handleAgentFailure(
                error.getRequestId(),
                organizationOf(error.getOrganizationId(), verified),
                UserFacingErrorMessages.resolveCode(error.getErrorCode(), error.getLastReason()),
                error.getErrorDetail(),
                parseDateTime(error.getRespondedAt()));
        }

        // The timeline event and its audit row in one transaction of their own: this handler runs with none
        // (its message-queue calls must stay outside one). The row's reason is the agent's code, RETRY_GIVE_UP unwrapped;
        // never its detail.
        transactionTemplate.executeWithoutResult(status -> {
            if (insertEvent(xref, cert.getOrganizationId(), derivedEventType,
                    prevStatus, cert.getStatus(),
                    error.getRequestId(), error.getCorrelationId(), EventSource.AGENT.value(),
                    Map.of("errorCode", orEmpty(error.getErrorCode()),
                           "errorDetail", orEmpty(error.getErrorDetail())))) {
                recordAgentFailure(error, cert, verified);
            }
        });

        saveFailureAlert(cert, error.getOriginalMessageType(), error.getErrorCode(), error.getErrorDetail(),
                error.getLastReason(), error.getRetryAfterUtc());

        return new NotifPayload(notifAction, error.getOrganizationId(), xref,
                Map.of("errorCode", orEmpty(error.getErrorCode()),
                   "domain", orEmpty(cert.getDomain()),
                   "requestId", orEmpty(error.getRequestId())));
    }

    /** Statuses a certificate only reaches once it was issued: an issuance failure cannot apply to them. */
    private static final java.util.Set<String> ISSUED_STATUSES = java.util.Set.of(
            CertificateStatus.ACTIVE.name(), CertificateStatus.RENEW_SUCCESS.name(),
            CertificateStatus.RENEWING.name(), CertificateStatus.EXPIRED.name(),
            CertificateStatus.REVOKING.name(), CertificateStatus.REVOKED.name(),
            CertificateStatus.REVOCATION_FAILED.name());

    /**
     * Why an agent failure is stale and must not be applied, or null when it applies. Commands are delivered at
     * least once, so two deliveries of one command can both run: when one succeeded and the other then fails, the
     * failure arrives after the success and must not downgrade it. Matched on the request id where there is one:
     *
     * <ul>
     *   <li>issuance: the request already has its success, or the certificate is already issued;</li>
     *   <li>renewal: the request already has its success;</li>
     *   <li>deployment: the deployment of the request already succeeded.</li>
     * </ul>
     */
    private String staleFailureReason(AgentErrorMessage error, CertificateEntity cert, VerifiedAgentMessage verified) {
        String type = error.getOriginalMessageType();
        String requestId = error.getRequestId();
        boolean hasRequest = requestId != null && !requestId.isBlank();
        if (isIssuanceFailureType(type)) {
            if (hasRequest && eventRepository.existsByRequestIdAndEventType(requestId,
                    CertEventType.ISSUANCE_SUCCESS.name())) {
                return "the request already issued the certificate";
            }
            if (ISSUED_STATUSES.contains(cert.getStatus())) {
                return "the certificate is already " + cert.getStatus();
            }
        } else if ("CERT_RENEWAL".equals(type)) {
            if (hasRequest && eventRepository.existsByRequestIdAndEventType(requestId,
                    CertEventType.RENEWAL_SUCCESS.name())) {
                return "the request already renewed the certificate";
            }
        } else if ("CERT_DEPLOYMENT".equals(type) && hasRequest) {
            Optional<com.certmanagement.entity.DeploymentEntity> deployment =
                    deploymentExecutionService.findDeployment(requestId,
                            organizationOf(error.getOrganizationId(), verified));
            if (deployment != null && deployment.isPresent()
                    && com.certmanagement.enums.DeploymentStatus.SUCCESS.name().equals(deployment.get().getStatus())) {
                return "the deployment already succeeded";
            }
        }
        return null;
    }

    /** The audit row of an agent's failure of a certificate command; nothing for a command the trail has no event for. */
    private void recordAgentFailure(AgentErrorMessage error, CertificateEntity cert, VerifiedAgentMessage verified) {
        AuditReason reason = AuditReason.fromAgent(error.getErrorCode(), error.getLastReason());
        Integer requestedBy = requestedBy(error.getRequestId());
        String type = error.getOriginalMessageType();
        if (isIssuanceFailureType(type)) {
            certificateAudit.issueFailed(cert, reason, requestedBy);
        } else if ("CERT_RENEWAL".equals(type)) {
            certificateAudit.renewalFailed(cert, reason, requestedBy);
        } else if ("CERT_REVOCATION_COMMAND".equals(type)) {
            certificateAudit.revocationFailed(cert, reason, requestedBy);
        } else if ("CERT_DEPLOYMENT".equals(type)) {
            Optional<com.certmanagement.entity.DeploymentEntity> deployment = error.getRequestId() == null
                    ? Optional.empty()
                    : deploymentExecutionService.findDeployment(error.getRequestId(),
                            organizationOf(error.getOrganizationId(), verified));
            certificateAudit.deploymentFailed(cert,
                    deployment.map(com.certmanagement.entity.DeploymentEntity::getTargetType).orElse(null),
                    deployment.map(com.certmanagement.entity.DeploymentEntity::getFlowType).orElse(null),
                    reason, requestedBy);
        }
    }

    /**
     * CertPing acting on an agent's response: the rows written while it is handled are CertPing's, under the
     * message's correlation id (and, from the MDC, its request id), in the organization the message was proven to
     * come from.
     */
    private AuditScope agentScope(String bodyOrganizationId, VerifiedAgentMessage verified, String correlationId) {
        return AuditScope.system(CertificateAuditRecorder.AGENT_JOB, organizationOf(bodyOrganizationId, verified),
                emptyToNull(correlationId));
    }

    /** The member whose request {@code requestId} answers, by id; null when CertPing made it (a job) or unknown. */
    private Integer requestedBy(String requestId) {
        if (isBlank(requestId)) {
            return null;
        }
        return eventRepository.findFirstRequesterUserId(requestId, EventSource.CERT_MANAGER.value()).orElse(null);
    }

    private boolean isIssuanceFailureType(String originalMessageType) {
        return "CERT_ISSUANCE".equals(originalMessageType)
                || "CERT_MANUAL_TXT_REQUEST".equals(originalMessageType)
                || "CERT_MANUAL_DNS_VALIDATE".equals(originalMessageType);
    }

    private Optional<CertificateEntity> resolveRenewingCertForFailure(CertificateEntity cert) {
        if (CertificateStatus.RENEWING.name().equals(cert.getStatus())) {
            return Optional.of(cert);
        }
        if (CertificateStatus.PENDING.name().equals(cert.getStatus())
                || CertificateStatus.RENEWAL_FAILED.name().equals(cert.getStatus())) {
            return certificateRepository.findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                    cert.getUserDomainCertId(), CertificateStatus.RENEWING.name());
        }
        return Optional.empty();
    }

    private Optional<CertificateEntity> findActiveByUserDomainCertId(Long userDomainCertId) {
        if (userDomainCertId == null) {
            return Optional.empty();
        }
        Optional<CertificateEntity> found = certificateRepository
                .findTopByUserDomainCertIdAndStatusAndDeletedAtIsNullOrderByCreatedAtDesc(
                        userDomainCertId,
                        CertificateStatus.ACTIVE.name());
        return found != null ? found : Optional.empty();
    }

    private String derivePostRenewalFailureStatus(CertificateEntity previousCert) {
        OffsetDateTime validTo = previousCert.getValidTo();
        if (validTo != null && validTo.isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            return CertificateStatus.EXPIRED.name();
        }
        return CertificateStatus.ACTIVE.name();
    }

    private void handleAgentHealthHeartbeat(AgentHealthHeartbeat heartbeat) {
        if (heartbeat.getOrganizationId() == null || heartbeat.getOrganizationId().isBlank()) {
            log.warn("AGENT_HEALTH_HEARTBEAT missing organizationId, skipping persistence");
            return;
        }
        try {
            if (agentHealthService.saveHeartbeat(heartbeat)) {
                log.info("Persisted AGENT_HEALTH_HEARTBEAT for organizationId={} listening={}",
                        heartbeat.getOrganizationId(), heartbeat.getListening());
            }
        } catch (UnknownOrganizationForHeartbeatException e) {
            log.warn(
                    "AGENT_HEALTH_HEARTBEAT for unknown organizationId={} — acknowledging message to avoid redelivery",
                    e.getOrganizationId());
        }
    }

    // ------------------------------------------------------------------ //
    //  Akamai-special post-issuance dispatch
    // ------------------------------------------------------------------ //

    /**
     * Dispatches a successfully issued Akamai-special cert to all AKAMAI_CPS deployment
     * credentials configured for the same UDC.
     *
     * <p>An Akamai-special cert must ONLY be deployed to AKAMAI_CPS targets — its private
     * key is held by Akamai and the cert cannot be used on any other platform.
     */
    private DeploymentExecutionService.AutoDeployOutcome dispatchAkamaiSpecialCert(
            CertificateEntity cert, String certSecretHandle, String organizationId) {
        List<String> akamaiCredXrefs = akamaiDeploymentCredentials(cert);
        if (akamaiCredXrefs.isEmpty()) {
            return DeploymentExecutionService.AutoDeployOutcome.NOTHING_TO_DEPLOY;
        }
        if (!deploymentExecutionService.isAutoDeployEnabled(Long.parseLong(organizationId))) {
            log.info("[AKAMAI_CPS_POST_ISSUANCE] CERTIFICATE_DEPLOYMENT is off for org={} — not deploying xref={}",
                    organizationId, cert.getCertificateXref());
            return DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF;
        }

        log.info("[AKAMAI_CPS_POST_ISSUANCE] Dispatching special cert xref={} to {} AKAMAI_CPS target(s)",
                cert.getCertificateXref(), akamaiCredXrefs.size());
        deploymentExecutionService.dispatchAll(
                Long.parseLong(organizationId), cert, certSecretHandle, akamaiCredXrefs,
                FLOW_POST_AKAMAI_ISSUANCE);
        return DeploymentExecutionService.AutoDeployOutcome.DISPATCHED;
    }

    /** {@link DeploymentExecutionService#planAutoDeploy} for an Akamai-special cert: reads only. */
    private DeploymentExecutionService.AutoDeployOutcome planAkamaiDeploy(CertificateEntity cert,
                                                                         boolean deploymentEnabled) {
        if (akamaiDeploymentCredentials(cert).isEmpty()) {
            return DeploymentExecutionService.AutoDeployOutcome.NOTHING_TO_DEPLOY;
        }
        return deploymentEnabled ? DeploymentExecutionService.AutoDeployOutcome.DISPATCHED
                : DeploymentExecutionService.AutoDeployOutcome.SKIPPED_FEATURE_OFF;
    }

    /** The AKAMAI_CPS deployment credentials configured for the cert's UDC (logged when there are none). */
    private List<String> akamaiDeploymentCredentials(CertificateEntity cert) {
        DomainCredentialConfigEntity credConfig = domainCredConfigRepository
                .findByUserDomainCertId(cert.getUserDomainCertId())
                .orElse(null);
        if (credConfig == null || credConfig.getDeploymentTargets() == null
                || credConfig.getDeploymentTargets().isEmpty()) {
            log.info("[AKAMAI_CPS_POST_ISSUANCE] No deployment targets for special cert xref={} — cert stays ACTIVE",
                    cert.getCertificateXref());
            return List.of();
        }
        // Bounded by the UDC's configured targets (a handful).
        List<String> akamaiCredXrefs = credConfig.getDeploymentTargets().stream()
                .filter(xref -> {
                    try {
                        return credentialReferenceRepository
                                .findByCredentialXref(xref)
                                .map(c -> AkamaiSpecialIssuanceService.AKAMAI_CPS.equals(c.getProvider()))
                                .orElse(false);
                    } catch (Exception e) {
                        log.warn("[AKAMAI_CPS_POST_ISSUANCE] Could not resolve credXref={}: {}",
                                xref, e.getMessage());
                        return false;
                    }
                })
                .toList();
        if (akamaiCredXrefs.isEmpty()) {
            log.warn("[AKAMAI_CPS_POST_ISSUANCE] No AKAMAI_CPS credentials found for special cert xref={}",
                    cert.getCertificateXref());
        }
        return akamaiCredXrefs;
    }

    // ------------------------------------------------------------------ //
    //  Manual issuance handler
    // ------------------------------------------------------------------ //

    /**
     * Handles {@code CERT_MANUAL_TXT_RESPONSE} from the agent.
     *
     * <p>Stores the ACME order state in {@code cert_manual_issuance_state} and flips the
     * certificate status to {@code AWAITING_DNS}. No notification is published — the UI
     * discovers the status change by polling {@code GET /api/v1/certs/{certXref}/txt-records}.
     */
    private NotifPayload handleManualTxtResponse(CertManualTxtResponse response,
                                                 VerifiedAgentMessage verified) {
        String xref = response.getCertificateXref();
        log.info("CERT_MANUAL_TXT_RESPONSE: xref={}", xref);

        CertificateEntity cert = findCertificateForOrganization(xref, verified)
                .orElseGet(() -> {
                    log.error("Certificate not found for xref={} — ignoring CERT_MANUAL_TXT_RESPONSE", xref);
                    return null;
                });
        if (cert == null) return null;

        if (CertificateStatus.CANCELLED_MANUAL.name().equals(cert.getStatus())) {
            log.warn("Ignoring CERT_MANUAL_TXT_RESPONSE for cancelled manual flow xref={}", xref);
            manualIssuanceStateRepository.deleteByCertXref(xref);
            return null;
        }

        String txtJson;
        try {
            txtJson = objectMapper.writeValueAsString(response.getTxtRecords());
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize txtRecords for xref=" + xref, e);
        }

        CertManualIssuanceStateEntity state = CertManualIssuanceStateEntity.builder()
            .certXref(xref)
                .organizationId(cert.getOrganizationId())
                .acmeOrderUrl(response.getAcmeOrderUrl())
                .acmeAccountHandle(response.getAcmeAccountHandle())
                .txtRecords(txtJson)
                .createdAt(OffsetDateTime.now(ZoneOffset.UTC))
                .expiresAt(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(55)) // ACME orders expire ~60 min
                .build();
        manualIssuanceStateRepository.save(state);

        cert.setStatus(CertificateStatus.AWAITING_DNS.name());
        cert.setAcmeAccountHandle(response.getAcmeAccountHandle());
        certificateRepository.save(cert);

        insertEvent(xref, cert.getOrganizationId(),
                CertEventType.MANUAL_TXT_RECEIVED.name(),
                CertificateStatus.PENDING_DNS.name(), CertificateStatus.AWAITING_DNS.name(),
                response.getRequestId(), response.getCorrelationId(), EventSource.AGENT.value(),
                Map.of("domain", orEmpty(cert.getDomain()),
                       "recordCount", String.valueOf(
                           response.getTxtRecords() != null ? response.getTxtRecords().size() : 0)));

        int recordCount = response.getTxtRecords() != null ? response.getTxtRecords().size() : 0;
        return new NotifPayload("CERT_MANUAL_TXT_READY", cert.getOrganizationId().toString(), xref,
            Map.of("domain", orEmpty(cert.getDomain()),
                   "recordCount", String.valueOf(recordCount),
                   "requestId", orEmpty(response.getRequestId())));
    }

    // ------------------------------------------------------------------ //
    //  Helpers
    // ------------------------------------------------------------------ //

    /**
     * Loads DomainCredentialConfigEntity for a certificate.
     * Primary path: via renewal schedule FK (schedule → credConfig ID).
     * Fallback: directly via userDomainCertId when the schedule row is missing
     *           (recovery case — schedule was never created or was deleted).
     * Returns null if neither path succeeds (logged as error).
     */
    private DomainCredentialConfigEntity loadCredConfigForCert(CertificateEntity cert) {
        Optional<RenewalScheduleEntity> scheduleOpt =
                renewalScheduleRepository.findByCertificateXref(cert.getCertificateXref());
        if (scheduleOpt.isPresent()) {
            return domainCredConfigRepository
                    .findById(scheduleOpt.get().getDomainCredentialConfigId())
                    .orElseGet(() -> {
                        log.error("DomainCredentialConfig missing for schedule of xref={}",
                                cert.getCertificateXref());
                        return null;
                    });
        }
        // Schedule missing — fall back to loading by userDomainCertId
        log.warn("RenewalSchedule missing for xref={} — loading credConfig via userDomainCertId",
                cert.getCertificateXref());
        return domainCredConfigRepository
                .findByUserDomainCertId(cert.getUserDomainCertId())
                .orElseGet(() -> {
                    log.error("No DomainCredentialConfig found for xref={} via any path",
                            cert.getCertificateXref());
                    return null;
                });
    }

    /**
     * Creates a recovery renewal schedule when the original schedule row is missing, enabled only when
     * {@code autoRenew} is true; an issued certificate's carries {@code issuedHoldStatus}.
     *
     * @return whether an enabled schedule now exists
     */
    private boolean createRecoverySchedule(CertificateEntity cert,
                                           DomainCredentialConfigEntity credConfig,
                                           boolean isRenewal,
                                           boolean autoRenew,
                                           String issuedHoldStatus) {
        if (credConfig == null || cert.getCertSecretHandle() == null || cert.getValidTo() == null) {
            log.error("Cannot create recovery renewal schedule for xref={}: " +
                      "missing credConfig, certSecretHandle, or validTo", cert.getCertificateXref());
            return false;
        }
        RenewalScheduleEntity.RenewalScheduleEntityBuilder builder = RenewalScheduleEntity.builder()
                .certificateXref(cert.getCertificateXref())
                .domainCredentialConfigId(credConfig.getId())
                .caProvider(cert.getCaProvider())
                .acmeAccountHandle(cert.getAcmeAccountHandle())
                .caCredentialHandle(cert.getCaCredentialHandle())
                .orderId(cert.getOrderId())
                .certSecretHandle(cert.getCertSecretHandle())
                .validTo(cert.getValidTo())
                .renewalEligibleAt(RenewalTiming.eligibleAt(cert.getValidFrom(), cert.getValidTo(), RenewalTiming.DEFAULT_WINDOW_DAYS))
                .enabled(autoRenew);
        if (isRenewal) {
            builder.lastRenewalAt(OffsetDateTime.now(ZoneOffset.UTC))
                   .lastRenewalStatus(RenewalStatus.SUCCESS.name());
        } else {
            builder.lastRenewalStatus(issuedHoldStatus);
        }
        renewalScheduleRepository.save(builder.build());
        log.info("Created recovery renewal schedule for xref={} (enabled={})", cert.getCertificateXref(), autoRenew);
        return autoRenew;
    }

    /**
     * Saves a timeline event unless one of the type was recorded for the request already.
     *
     * @return whether it was saved: the audit row for the same step is written only then, so a redelivered
     *         message writes neither twice
     */
    private boolean insertEvent(String xref, Long organizationId, String eventType,
                                String fromStatus, String toStatus,
                                String requestId, String correlationId,
                                String source, Map<String, Object> details) {
        if (requestId != null && eventRepository.existsByRequestIdAndEventType(requestId, eventType)) {
            log.info("Duplicate event suppressed (already recorded): xref={}, requestId={}, eventType={}",
                    xref, requestId, eventType);
            return false;
        }
        try {
            // Safe without an organization filter: callers reach this only after the
            // certificate was resolved through findCertificateForOrganization.
            Integer eventUserId = certificateRepository.findByCertificateXref(xref)
                .map(CertificateEntity::getUserDomainCert)
                .map(udc -> udc != null ? udc.getUserId() : null)
                .orElse(null);

            CertificateEventEntity event = CertificateEventEntity.builder()
                    .certificateXref(xref)
                    .organizationId(organizationId)
                    .eventType(eventType)
                    .fromStatus(fromStatus)
                    .toStatus(toStatus)
                    .requestId(requestId)
                    .correlationId(correlationId)
                .userId(eventUserId)
                    .source(source)
                    .details(objectMapper.writeValueAsString(details))
                    .build();
            eventRepository.save(event);
            return true;
        } catch (Exception e) {
            log.error("Failed to insert certificate_event for xref={}: {}", xref, e.getMessage(), e);
            return false;
        }
    }

    private OffsetDateTime parseDateTime(String iso) {
        if (iso == null || iso.isBlank()) return null;
        try { return OffsetDateTime.parse(iso); }
        catch (Exception e) { return null; }
    }

    private String orEmpty(String value) {
        return value != null ? value : "";
    }

    private static String emptyToNull(String value) {
        return (value == null || value.isEmpty()) ? null : value;
    }

    private static Long parseOrganizationId(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private String nameOf(TargetType type) {
        return type != null ? type.name() : "";
    }

    private void upsertCryptoMetadata(String certificateXref, CertIssuanceResponse response) {
        if (response.getSignatureAlgorithmOid() == null
                && response.getSubjectDn() == null
                && response.getCommonName() == null
                && response.getPublicKeyCurve() == null
                && response.getKeyUsage() == null
                && response.getExtendedKeyUsage() == null
                && response.getSubjectKeyIdentifier() == null
                && response.getAuthorityKeyIdentifier() == null) {
            return;
        }
        try {
            CertificateCryptoMetadataEntity meta = cryptoMetadataRepository
                    .findByCertificateXref(certificateXref)
                    .orElseGet(() -> CertificateCryptoMetadataEntity.builder()
                            .certificateXref(certificateXref)
                            .build());
            meta.setSignatureAlgorithmOid(response.getSignatureAlgorithmOid());
            meta.setSubjectDn(response.getSubjectDn());
            meta.setCommonName(response.getCommonName());
            meta.setPublicKeyCurve(response.getPublicKeyCurve());
            meta.setKeyUsage(response.getKeyUsage());
            meta.setExtendedKeyUsage(response.getExtendedKeyUsage());
            meta.setSubjectKeyIdentifier(response.getSubjectKeyIdentifier());
            meta.setAuthorityKeyIdentifier(response.getAuthorityKeyIdentifier());
            cryptoMetadataRepository.save(meta);
        } catch (Exception e) {
            log.error("Failed to upsert crypto metadata for xref={}: {}", certificateXref, e.getMessage(), e);
        }
    }

    private String validateTargetResourceIdFormat(String resourceId, TargetType targetType) {
        if (targetType == null) return null;
        return switch (targetType) {
            case AZURE_KV -> resourceId.startsWith("https://") ? null
                    : "AZURE_KV targetResourceId must start with 'https://', got: '" + resourceId + "'";
            case AWS_ACM  -> resourceId.startsWith("arn:aws:acm:") ? null
                    : "AWS_ACM targetResourceId must start with 'arn:aws:acm:', got: '" + resourceId + "'";
            default -> null;
        };
    }

    /**
     * Applies a terminal failure to a certificate row: the unwrapped (RETRY_GIVE_UP → inner reason)
     * error code, the raw detail for internal audit, the timestamp, and the operation's correlation
     * id so the user-facing message and the support "Reference ID" both reflect the real cause.
     */
    private void applyCertFailure(CertificateEntity c, AgentErrorMessage error, OffsetDateTime at) {
        c.setLastErrorCode(UserFacingErrorMessages.resolveCode(error.getErrorCode(), error.getLastReason()));
        c.setLastErrorMessage(error.getErrorDetail());
        c.setLastErrorAt(at);
        c.setCorrelationId(error.getCorrelationId());
    }

    private void saveFailureAlert(CertificateEntity cert,
                                  String originalMessageType,
                                  String errorCode,
                                  String errorDetail,
                                  String lastReason,
                                  String retryAfterUtc) {
        try {
            AlertStatus alertStatus = "CERT_RENEWAL".equals(originalMessageType)
                    ? AlertStatus.RENEWAL_FAILED
                    : AlertStatus.FAILED;

            AlertTypeEnum alertType = determineAlertType(originalMessageType);

            // RETRY_GIVE_UP wraps an inner classifier code; show the user that instead.
            String message = UserFacingErrorMessages.forCode(errorCode, lastReason);
            if (retryAfterUtc != null && !retryAfterUtc.isBlank()) {
                message = message + " Try again after " + retryAfterUtc + ".";
            }

            // The inbound message's trace id (stamped on the MDC for the duration of processing —
            // the same correlationId carried on the event/deployment rows). Surfaced to the user as
            // a support "Reference ID"; null when the originating message had none.
            String correlationId = MDC.get("correlationId");

            AlertEntity alert = AlertEntity.builder()
                    .organizationId(cert.getOrganizationId())
                    .domain(cert.getDomain())
                    .alertType(alertType)
                    .status(alertStatus)
                    .severity(AlertSeverity.CRITICAL)
                    .message(message)
                    .errorCode(errorCode)
                    .errorDetail(errorDetail)
                    .correlationId(correlationId)
                    .unread(true)
                    .build();

            alertService.saveAlert(alert);
        } catch (Exception ex) {
            log.error("Failed to save failure alert for cert xref={}: {}", cert.getCertificateXref(), ex.getMessage(), ex);
        }
    }

    private AlertTypeEnum determineAlertType(String originalMessageType) {
        return switch (originalMessageType != null ? originalMessageType : "") {
            case "CERT_DEPLOYMENT" -> AlertTypeEnum.DEPLOYMENT_FAILURE;
            default -> AlertTypeEnum.CERTIFICATE_FAILURE;
        };
    }

    private String deriveEventType(String originalMessageType) {
        if (originalMessageType == null) return CertEventType.STATUS_CHANGED.name();
        return switch (originalMessageType) {
            case "CERT_ISSUANCE",
                 "CERT_MANUAL_TXT_REQUEST",
                 "CERT_MANUAL_DNS_VALIDATE" -> CertEventType.ISSUANCE_FAILED.name();
            case "CERT_RENEWAL"             -> CertEventType.RENEWAL_FAILED.name();
            case "CERT_DEPLOYMENT"          -> CertEventType.DEPLOYMENT_FAILED.name();
            case "CERT_REVOCATION_COMMAND"  -> CertEventType.REVOCATION_FAILED.name();
            default                         -> CertEventType.STATUS_CHANGED.name();
        };
    }

    private String determineFailureAction(String originalMessageType) {
        if (originalMessageType == null) return "CERT_ISSUANCE_FAILED";
        return switch (originalMessageType) {
            case "CERT_ISSUANCE"           -> "CERT_ISSUANCE_FAILED";
            case "CERT_MANUAL_TXT_REQUEST" -> "CERT_ISSUANCE_FAILED";
            case "CERT_MANUAL_DNS_VALIDATE" -> "CERT_ISSUANCE_FAILED";
            case "CERT_RENEWAL"            -> "CERT_RENEWAL_FAILED";
            case "CERT_DEPLOYMENT"         -> "CERT_DEPLOYMENT_FAILED";
            case "CERT_REVOCATION_COMMAND" -> "CERT_REVOCATION_FAILED";
            default                        -> "CERT_ISSUANCE_FAILED";
        };
    }
}
