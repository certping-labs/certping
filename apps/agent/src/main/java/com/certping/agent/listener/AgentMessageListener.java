// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.transport.DeadLetterOptions;
import com.certping.agent.exception.DuplicateDeliveryException;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryMetrics;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.MessageType;
import com.certping.agent.model.message.AgentErrorMessage;
import com.certping.agent.model.message.AgentDeepHealthCheckMessage;
import com.certping.agent.model.message.AgentHeartbeatCadenceUpdateMessage;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.model.message.DeviceIdentitySyncMessage;
import com.certping.agent.model.message.IotDeviceSyncMessage;
import com.certping.agent.model.message.IotCertificateRevocationMessage;
import com.certping.agent.model.message.IotIntuneRevocationPollMessage;
import com.certping.agent.model.message.IotIntuneRevocationUploadMessage;
import com.certping.agent.model.message.CertManualTxtRequestMessage;
import com.certping.agent.model.message.CertManualValidateMessage;
import com.certping.agent.model.message.CertRenewalMessage;
import com.certping.agent.model.message.CertOwnSecretDeleteMessage;
import com.certping.agent.model.message.CertSecretDeleteMessage;
import com.certping.agent.model.message.CertRevocationMessage;
import com.certping.agent.model.message.CertificateProfileMessage;
import com.certping.agent.model.message.CertificateProfileSyncMessage;
import com.certping.agent.processor.CertDiscoveryProcessor;
import com.certping.agent.processor.DeviceIdentitySyncProcessor;
import com.certping.agent.processor.IotDeviceSyncProcessor;
import com.certping.agent.processor.IotCertificateRevocationProcessor;
import com.certping.agent.processor.IotIntuneRevocationProcessor;
import com.certping.agent.processor.CertSecretDeleteProcessor;
import com.certping.agent.processor.CertDeploymentProcessor;
import com.certping.agent.processor.CertIssuanceProcessor;
import com.certping.agent.processor.AgentDeepHealthCheckProcessor;
import com.certping.agent.processor.AgentHeartbeatCadenceProcessor;
import com.certping.agent.processor.CertManualIssuanceProcessor;
import com.certping.agent.processor.CertRenewalProcessor;
import com.certping.agent.processor.CertOwnSecretDeleteProcessor;
import com.certping.agent.processor.CertRevocationProcessor;
import com.certping.agent.processor.CertificateProfileProcessor;
import com.certping.agent.processor.CertificateProfileSyncProcessor;
import com.certping.agent.processor.StoredResultPublisher;
import tools.jackson.databind.ObjectMapper;
import io.opentelemetry.api.trace.Span;
import lombok.extern.slf4j.Slf4j;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.MDC;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class AgentMessageListener {

    static final String RESPONSE_PUBLISH_GIVE_UP_METRIC = "agent.response.publish.giveup.count";

    private final ObjectMapper objectMapper;
    private final AgentInboundMessageRouting inboundMessageRouting;
    private final AgentMessageSender sender;
    private final CertIssuanceProcessor issuanceProcessor;
    private final CertRenewalProcessor renewalProcessor;
    private final CertDeploymentProcessor deploymentProcessor;
    private final CertManualIssuanceProcessor manualIssuanceProcessor;
    private final CertRevocationProcessor certRevocationProcessor;
    private final CertOwnSecretDeleteProcessor certKvSecretDeleteProcessor;
    private final AgentHeartbeatCadenceProcessor cadenceProcessor;
    private final AgentDeepHealthCheckProcessor deepHealthCheckProcessor;
    private final CertSecretDeleteProcessor certKvDeleteProcessor;
    private final ScheduledRetryService scheduledRetryService;
    private final CertDiscoveryProcessor certDiscoveryProcessor;
    private final DeviceIdentitySyncProcessor deviceIdentitySyncProcessor;
    private final IotDeviceSyncProcessor iotDeviceSyncProcessor;
    private final IotCertificateRevocationProcessor iotCertificateRevocationProcessor;
    private final IotIntuneRevocationProcessor iotIntuneRevocationProcessor;
    private final CertificateProfileProcessor certificateProfileProcessor;
    private final CertificateProfileSyncProcessor certificateProfileSyncProcessor;
    private final MeterRegistry meterRegistry;
    private final CheckpointStagingPurger checkpointStagingPurger;
    private final AttemptRecords attemptRecords;

    public AgentMessageListener(
            ObjectMapper objectMapper,
            AgentInboundMessageRouting inboundMessageRouting,
            ScheduledRetryService scheduledRetryService,
            @Lazy AgentMessageSender sender,
            CertIssuanceProcessor issuanceProcessor,
            CertRenewalProcessor renewalProcessor,
            CertDeploymentProcessor deploymentProcessor,
            CertManualIssuanceProcessor manualIssuanceProcessor,
            CertRevocationProcessor certRevocationProcessor,
            CertOwnSecretDeleteProcessor certKvSecretDeleteProcessor,
            AgentHeartbeatCadenceProcessor cadenceProcessor,
            AgentDeepHealthCheckProcessor deepHealthCheckProcessor,
            CertSecretDeleteProcessor certKvDeleteProcessor,
            CertDiscoveryProcessor certDiscoveryProcessor,
            DeviceIdentitySyncProcessor deviceIdentitySyncProcessor,
            IotDeviceSyncProcessor iotDeviceSyncProcessor,
            IotCertificateRevocationProcessor iotCertificateRevocationProcessor,
            IotIntuneRevocationProcessor iotIntuneRevocationProcessor,
            CertificateProfileProcessor certificateProfileProcessor,
            CertificateProfileSyncProcessor certificateProfileSyncProcessor,
            MeterRegistry meterRegistry,
            CheckpointStagingPurger checkpointStagingPurger,
            AttemptRecords attemptRecords) {
        this.objectMapper = objectMapper;
        this.inboundMessageRouting = inboundMessageRouting;
        this.sender = sender;
        this.issuanceProcessor = issuanceProcessor;
        this.renewalProcessor = renewalProcessor;
        this.deploymentProcessor = deploymentProcessor;
        this.manualIssuanceProcessor = manualIssuanceProcessor;
        this.certRevocationProcessor = certRevocationProcessor;
        this.certKvSecretDeleteProcessor = certKvSecretDeleteProcessor;
        this.cadenceProcessor = cadenceProcessor;
        this.deepHealthCheckProcessor = deepHealthCheckProcessor;
        this.certKvDeleteProcessor = certKvDeleteProcessor;
        this.scheduledRetryService = scheduledRetryService;
        this.certDiscoveryProcessor = certDiscoveryProcessor;
        this.deviceIdentitySyncProcessor = deviceIdentitySyncProcessor;
        this.iotDeviceSyncProcessor = iotDeviceSyncProcessor;
        this.iotCertificateRevocationProcessor = iotCertificateRevocationProcessor;
        this.iotIntuneRevocationProcessor = iotIntuneRevocationProcessor;
        this.certificateProfileProcessor = certificateProfileProcessor;
        this.certificateProfileSyncProcessor = certificateProfileSyncProcessor;
        this.meterRegistry = meterRegistry;
        this.checkpointStagingPurger = checkpointStagingPurger;
        this.attemptRecords = attemptRecords;
    }

    public void onMessage(InboundContext context) {
        InboundMessage message = context.getMessage();
        String messageId = message.getMessageId();
        String messageTypeStr = (String) message.getApplicationProperties().get("MessageType");
        long startedAtNanos = System.nanoTime();

        String requestId = messageId;
        String correlationId = null;
        String organizationId = null;
        String certificateXref = null;
        String sourceXref = null;
        String syncXref = null;

        try {
            String body = message.getBody().toString();

            // Parse the envelope once so routing, logging, and handler dispatch all work
            // off the same source data.
            var json = objectMapper.readTree(body);
            requestId = json.path("requestId").asString(messageId);
            correlationId = json.path("correlationId").asString();
            organizationId = json.path("organizationId").asString("");
            certificateXref = json.path("certificateXref").asString();
            sourceXref = json.path("sourceXref").asString(null);
            syncXref = json.path("syncXref").asString(null);

            putMdc("requestId", requestId);
            putMdc("correlationId", correlationId);
            putMdc("organizationId", organizationId);
            putMdc("messageType", messageTypeStr);
            putMdc("messageId", messageId);

            Span.current().setAttribute("request.id", requestId);
            Span.current().setAttribute("correlation.id", correlationId);
            Span.current().setAttribute("organization.id", organizationId);
            Span.current().setAttribute("certificate.xref", certificateXref);
            Span.current().setAttribute("message.type", messageTypeStr);
            Span.current().setAttribute("messaging.message.id", messageId);

            MessageType messageType = MessageType.fromString(messageTypeStr);
            String entityPath = safeEntityPath(context);
            putMdc("entityPath", entityPath);

            log.info(
                    "Message received: messageType={}, queue={}, deliveryCount={}, messageId={}",
                    messageTypeStr, entityPath, message.getDeliveryCount(), messageId);

            if (inboundMessageRouting.requiresOrganizationMatch(messageType)) {
                if (organizationId == null || organizationId.isBlank()) {
                    throw new PermanentAgentException("MISSING_ORGANIZATION_ID",
                            "Inbound message is missing organizationId for type=" + messageType);
                }

                if (!inboundMessageRouting.matchesConfiguredOrganization(organizationId)) {
                    completeWithoutProcessing(context,
                            "Ignoring inbound message due to organization mismatch type={} messageOrganizationId={} configuredOrganizationId={}",
                            messageType,
                            organizationId,
                            inboundMessageRouting.configuredOrganizationId());
                    return;
                }
            }

            switch (messageType) {
                case CERT_ISSUANCE -> {
                    putMdc("caProvider", json.path("caProvider").asString());
                    issuanceProcessor.process(
                            objectMapper.readValue(body, CertIssuanceMessage.class), context);
                }
                case CERT_RENEWAL -> {
                    putMdc("caProvider", json.path("caProvider").asString());
                    renewalProcessor.process(
                            objectMapper.readValue(body, CertRenewalMessage.class), context);
                }
                case CERT_DEPLOYMENT -> deploymentProcessor.process(
                        objectMapper.readValue(body, CertDeploymentMessage.class), context);

                case CERT_MANUAL_TXT_REQUEST -> manualIssuanceProcessor.processManualTxtRequest(
                        objectMapper.readValue(body, CertManualTxtRequestMessage.class), context);

                case CERT_MANUAL_DNS_VALIDATE -> manualIssuanceProcessor.processManualDnsValidation(
                        objectMapper.readValue(body, CertManualValidateMessage.class), context);
                case CERT_REVOCATION_COMMAND -> {
                    putMdc("caProvider", json.path("caProvider").asString());
                    certRevocationProcessor.process(
                            objectMapper.readValue(body, CertRevocationMessage.class), context);
                }
                case CERT_OWN_SECRET_DELETE -> certKvSecretDeleteProcessor.process(
                        objectMapper.readValue(body, CertOwnSecretDeleteMessage.class), context);
                case AGENT_HEARTBEAT_CADENCE_UPDATE -> cadenceProcessor.process(
                        objectMapper.readValue(body, AgentHeartbeatCadenceUpdateMessage.class), context);
                case AGENT_DEEP_HEALTH_CHECK -> deepHealthCheckProcessor.process(
                        objectMapper.readValue(body, AgentDeepHealthCheckMessage.class), context);

                case CERT_SECRET_DELETE_COMMAND -> certKvDeleteProcessor.process(
                        objectMapper.readValue(body, CertSecretDeleteMessage.class), context);

                case CERT_DISCOVERY -> certDiscoveryProcessor.process(
                        objectMapper.readValue(body, CertDiscoveryMessage.class), context);

                case DEVICE_IDENTITY_SYNC_COMMAND -> deviceIdentitySyncProcessor.process(
                        objectMapper.readValue(body, DeviceIdentitySyncMessage.class), context);

                case IOT_DEVICE_SYNC_COMMAND -> iotDeviceSyncProcessor.process(
                        objectMapper.readValue(body, IotDeviceSyncMessage.class), context);

                case IOT_CERTIFICATE_REVOCATION_COMMAND -> iotCertificateRevocationProcessor.process(
                        objectMapper.readValue(body, IotCertificateRevocationMessage.class), context);

                case IOT_INTUNE_REVOCATION_POLL_COMMAND -> iotIntuneRevocationProcessor.poll(
                        objectMapper.readValue(body, IotIntuneRevocationPollMessage.class), context);

                case IOT_INTUNE_REVOCATION_UPLOAD_COMMAND -> iotIntuneRevocationProcessor.upload(
                        objectMapper.readValue(body, IotIntuneRevocationUploadMessage.class), context);

                case IOT_CERTIFICATE_PROFILE_COMMAND -> certificateProfileProcessor.process(
                        objectMapper.readValue(body, CertificateProfileMessage.class), context);

                case IOT_CERTIFICATE_PROFILE_SYNC_COMMAND -> certificateProfileSyncProcessor.process(
                        objectMapper.readValue(body, CertificateProfileSyncMessage.class), context);

                default -> throw new PermanentAgentException(
                        "UNKNOWN_MESSAGE_TYPE", "No handler for MessageType: " + messageTypeStr);
            }

            log.info("Message processed successfully durationMs={}", elapsedMillis(startedAtNanos));

        } catch (DuplicateDeliveryException e) {
            log.info("Duplicate delivery settled without an error: {}", e.getMessage());
            try {
                context.complete();
            } catch (RuntimeException settleError) {
                log.warn("Duplicate delivery not settled: {}", settleError.getMessage());
            }

        } catch (RetryableAgentException e) {
            // Upstream told us when to retry (ACME Retry-After, provider 429/throttle). Re-schedule
            // on our own inbound queue with a ScheduledEnqueueTime so the worker is freed
            // immediately instead of blocking on the wait.
            handleRetryable(context, e.getErrorCode(), e.getMessage(), e.getRetryAfter(),
                    e.getCheckpoint(),
                    messageTypeStr, requestId, correlationId, organizationId, certificateXref,
                    sourceXref, syncXref);

        } catch (TransientAgentException e) {
            // Recoverable but no upstream hint — re-schedule with the blind backoff curve indexed
            // by the header-tracked RetryCount. Rescheduling, not abandon(), so a sustained outage does
            // not redeliver within seconds and dead-letter the message.
            handleRetryable(context, e.getErrorCode(), e.getMessage(), null,
                    null,
                    messageTypeStr, requestId, correlationId, organizationId, certificateXref,
                    sourceXref, syncXref);

        } catch (Throwable t) {
            // Universal failure path — every other throwable (PermanentAgentException, any
            // other Exception, NoClassDefFoundError / LinkageError / OOM, etc.) lands here
            // so
            // the agent always (a) tells the server what happened via AGENT_ERROR,
            // (b) dead-letters the message so it doesn't loop, and (c) keeps the poller
            // thread alive for subsequent messages. Catching Throwable (not just Exception)
            // stops a JVM-level Error from escaping the poller thread — which would
            // otherwise log the trace without MDC (no [req=corr=msg=org=] prefix) and
            // leave the message unsettled until max-delivery-count.
            ErrorClassification ec = classifyThrowable(t);
            if (ec.logAsError) {
                log.error("{} — dead-lettering: {} — {}", ec.logPrefix, ec.errorCode, ec.detail, t);
            } else {
                // PermanentAgentException carries an intentional, classified failure — its
                // message is the diagnostic, and including the stack trace would spam logs
                // without adding signal.
                log.error("{} — dead-lettering: {} — {}", ec.logPrefix, ec.errorCode, ec.detail);
            }
            // Permanent failures: errorCode IS the terminal reason, no inner lastReason / retryAfterUtc.
            meterRegistry.counter("agent.message.permanent.count",
                    "messageType", messageTypeStr == null ? "unknown" : messageTypeStr,
                    "errorCode", ec.errorCode == null ? "unknown" : ec.errorCode).increment();
            trySendAgentError(requestId, correlationId, organizationId, certificateXref,
                    sourceXref, syncXref, messageTypeStr, ec.errorCode, ec.detail, null, null);
            attemptRecords.fail(message, certificateXref);
            try {
                context.deadLetter(new DeadLetterOptions()
                        .setDeadLetterReason(ec.errorCode)
                        .setDeadLetterErrorDescription(ec.detail));
            } catch (Throwable settleError) {
                log.error("Failed to dead-letter message — will redeliver until max-delivery-count: {}",
                        settleError.getMessage());
            }
            // VirtualMachineError (OOM, StackOverflow) means the JVM is in an unrecoverable
            // state — settle the message first (so it doesn't redeliver forever after the
            // pod
            // restarts), then re-throw so the pod actually crashes and Kubernetes restarts
            // it.
            // Other Errors like NoClassDefFoundError are recoverable for subsequent
            // messages,
            // so we swallow them after settling.
            if (t instanceof VirtualMachineError vme) {
                throw vme;
            }
        } finally {
            MDC.clear();
        }
    }

    /**
     * Shared handler for both retryable exception types. Re-schedules the message on this agent's
     * own inbound queue (freeing the worker immediately) until the retry policy's budget for the
     * reason is spent, a single {@code retryAfter} exceeds the hard cap, or the retry would start past the
     * message's attempt deadline — then dead-letters with {@code RETRY_GIVE_UP} and emits an
     * {@code AGENT_ERROR} so the server (and the user) is told. A stored certificate's unsent result is
     * dead-lettered without an error instead.
     *
     * @param retryAfter exact upstream wait, or {@code null} to apply the blind backoff curve.
     */
    private void handleRetryable(InboundContext context,
            String errorCode, String message, Duration retryAfter,
            IssuanceCheckpoint checkpoint,
            String messageTypeStr,
            String requestId, String correlationId, String organizationId, String certificateXref,
            String sourceXref, String syncXref) {
        RetryPolicy policy = scheduledRetryService.policy();
        int retryCount = ScheduledRetryService.currentRetryCount(context.getMessage());
        boolean renewal = "CERT_RENEWAL".equals(messageTypeStr);
        Duration hardCap = policy.hardCapFor(renewal);

        Duration delay = ScheduledRetryService.pickDelay(retryAfter, retryCount, policy, hardCap);
        Optional<ScheduledRetryService.RetrySlot> slot = scheduledRetryService.slotFor(context.getMessage(), delay);
        boolean giveUp = policy.exhausted(errorCode, retryCount,
                        ScheduledRetryService.currentRetryCount(context.getMessage(), errorCode))
                || (retryAfter != null && retryAfter.compareTo(hardCap) > 0)
                || slot.isEmpty();

        if (giveUp && checkpoint != null && checkpoint.step() == IssuanceCheckpoint.Step.KV_STORED) {
            giveUpOnStoredResult(context, messageTypeStr, certificateXref, retryCount);
            return;
        }
        if (giveUp) {
            String detail = "RETRY_GIVE_UP: " + errorCode + " - " + message
                    + " (retryCount=" + retryCount + ", retryAfter=" + retryAfter + ")";
            // retryAfterUtc is only meaningful when upstream told us when capacity returns; for
            // blind backoff give-ups it's omitted so the server doesn't display a fake date.
            String retryAfterUtc = retryAfter == null ? null
                    : Instant.now().plus(retryAfter).toString();
            log.error("RetryGiveUp queue={} messageType={} retryCount={} lastReason={} finalRetryAfter={} retryAfterUtc={} detail=\"{}\"",
                    safeEntityPath(context), messageTypeStr, retryCount, errorCode, retryAfter, retryAfterUtc, detail);
            meterRegistry.counter(RetryMetrics.GIVE_UP,
                    "messageType", messageTypeStr == null ? "unknown" : messageTypeStr,
                    "reasonCode", errorCode == null ? "unknown" : errorCode).increment();
            trySendAgentError(requestId, correlationId, organizationId, certificateXref,
                    sourceXref, syncXref, messageTypeStr, "RETRY_GIVE_UP", detail, errorCode, retryAfterUtc);
            // Best-effort: purge the checkpoint staging slot before dead-lettering.
            // The issuance is dead — no future retry will read the staged key — so
            // nothing else removes the staged key. Failures are
            // swallowed inside the purger so they never block dead-lettering.
            checkpointStagingPurger.purgeIfPresent(context.getMessage());
            attemptRecords.fail(context.getMessage(), certificateXref);
            try {
                context.deadLetter(new DeadLetterOptions()
                        .setDeadLetterReason("RETRY_GIVE_UP")
                        .setDeadLetterErrorDescription(detail));
            } catch (Throwable settleError) {
                log.error("Failed to dead-letter RETRY_GIVE_UP message — will redeliver until max-delivery-count: {}",
                        settleError.getMessage());
            }
            return;
        }

        boolean recorded = recordBeforeRetry(context, certificateXref, checkpoint);
        if (!scheduledRetryService.scheduleRetry(context, slot.get(), errorCode, message, checkpoint)) {
            if (!recorded) {
                recordBeforeRetry(context, certificateXref, checkpoint);
            }
            // Most common cause of scheduleRetry failure is losing the server mid-flight (pod
            // shutdown, server unreachable, lock lost on a stalled processor). In that case the
            // abandon may fail too — the server redelivers when the lock expires. Log once at
            // info, swallow the secondary abandon error.
            log.info("Scheduled retry failed (reason={}) — the server will redeliver on lock expiry", errorCode);
            try {
                context.abandon();
            } catch (Exception abandonErr) {
                log.debug("Abandon also failed (expected when receiver is disposed): {}", abandonErr.getMessage());
            }
        }
    }

    /**
     * Records how far the attempt has got before its retry is sent, so a redelivery of this message resumes there. A
     * retry that cannot be recorded is sent anyway: it carries the checkpoint itself, an order is recorded before it
     * is sent, and not sending the retry would redeliver this message with its older checkpoint.
     *
     * @return whether the checkpoint is recorded, or needs no record
     */
    private boolean recordBeforeRetry(InboundContext context, String certificateXref,
                                      IssuanceCheckpoint checkpoint) {
        try {
            attemptRecords.save(context.getMessage(), certificateXref, checkpoint);
            return true;
        } catch (RuntimeException e) {
            log.warn("Attempt of xref={} not recorded before its retry; the retry carries its checkpoint: {}",
                    certificateXref, e.getMessage());
            return false;
        }
    }

    /**
     * Gives up sending the result of a certificate that is issued and stored. No {@code AGENT_ERROR} is sent: the
     * certificate exists, and an error would mark it failed. The dead-lettered message still carries the result for
     * a manual replay, and the server ends the attempt once its own horizon passes.
     */
    private void giveUpOnStoredResult(InboundContext context, String messageTypeStr,
                                      String certificateXref, int retryCount) {
        log.error("[RESPONSE_PUBLISH_GIVE_UP] queue={} messageType={} xref={} retryCount={}: the certificate is "
                        + "stored but its result could not be sent; replay it from the dead-letter queue",
                safeEntityPath(context), messageTypeStr, certificateXref, retryCount);
        meterRegistry.counter(RESPONSE_PUBLISH_GIVE_UP_METRIC,
                "messageType", messageTypeStr == null ? "unknown" : messageTypeStr).increment();
        try {
            context.deadLetter(new DeadLetterOptions()
                    .setDeadLetterReason(StoredResultPublisher.PUBLISH_FAILED)
                    .setDeadLetterErrorDescription("Certificate " + certificateXref
                            + " is stored; its result was not sent before the attempt deadline"));
        } catch (Throwable settleError) {
            log.error("Failed to dead-letter {} message — will redeliver until max-delivery-count: {}",
                    StoredResultPublisher.PUBLISH_FAILED, settleError.getMessage());
        }
    }

    /**
     * Classifies a throwable for the unified failure path: which error code to put
     * on the
     * AGENT_ERROR response & dead-letter reason, what detail string to use, and how
     * to log it.
     *
     * <p>
     * Three buckets:
     * <ul>
     * <li>{@link PermanentAgentException} — adapter/processor classified the
     * failure already.
     * Use its {@code errorCode} and message verbatim. No stack trace
     * (signal-to-noise).</li>
     * <li>{@link Error} (Exception's sibling — JVM-level / linkage problems) — log
     * a debugId,
     * expose the Error class & message so the server's logs are diagnosable, full
     * stack trace.</li>
     * <li>Any other {@link Exception} — opaque "UNEXPECTED_ERROR" with a debugId;
     * full stack trace
     * in the agent log so we can correlate. Don't leak internal exception messages
     * to
     * the server — they could contain PII or implementation details.</li>
     * </ul>
     */
    private static ErrorClassification classifyThrowable(Throwable t) {
        if (t instanceof PermanentAgentException pae) {
            return new ErrorClassification(pae.getErrorCode(), pae.getMessage(),
                    "Permanent error", false);
        }
        String debugId = UUID.randomUUID().toString();
        if (t instanceof Error) {
            String detail = "Fatal JVM error: " + t.getClass().getSimpleName()
                    + " — " + t.getMessage() + " (debugId=" + debugId + ")";
            return new ErrorClassification("FATAL_ERROR", detail, "Fatal error", true);
        }
        String detail = "Unexpected internal error (debugId=" + debugId + ")";
        return new ErrorClassification("UNEXPECTED_ERROR", detail, "Unexpected error", true);
    }

    /**
     * Internal helper record carrying the classification outputs from
     * {@link #classifyThrowable(Throwable)} to the catch block.
     */
    private record ErrorClassification(String errorCode, String detail,
            String logPrefix, boolean logAsError) {
    }

    private void completeWithoutProcessing(InboundContext context,
            String messageTemplate,
            Object... arguments) {
        log.warn(messageTemplate, arguments);
        try {
            context.complete();
        } catch (RuntimeException settleError) {
            log.warn("Failed to complete ignored message; it may be re-delivered: {}", settleError.getMessage());
        }
    }

    private static long elapsedMillis(long startedAtNanos) {
        return (System.nanoTime() - startedAtNanos) / 1_000_000L;
    }

    private static void putMdc(String key, String value) {
        if (value == null) {
            MDC.remove(key);
            return;
        }
        MDC.put(key, value);
    }

    private static String safeEntityPath(InboundContext context) {
        try {
            String entityPath = context.getEntityPath();
            return entityPath == null || entityPath.isBlank() ? "<unknown>" : entityPath;
        } catch (RuntimeException e) {
            return "<unknown>";
        }
    }

    private void trySendAgentError(String requestId, String correlationId,
            String organizationId, String certificateXref, String sourceXref, String syncXref,
            String originalMessageType, String errorCode, String errorDetail,
            String lastReason, String retryAfterUtc) {
        try {
            sender.sendAgentError(AgentErrorMessage.builder()
                    .requestId(requestId)
                    .correlationId(correlationId)
                    .organizationId(organizationId)
                    .certificateXref(certificateXref)
                    .sourceXref(blankToNull(sourceXref))
                    .syncXref(blankToNull(syncXref))
                    .originalMessageType(originalMessageType)
                    .errorCode(errorCode)
                    .errorDetail(errorDetail)
                    .respondedAt(Instant.now().toString())
                    .lastReason(lastReason)
                    .retryAfterUtc(retryAfterUtc)
                    .build());
        } catch (Exception ex) {
            log.error("CERT_STUCK: Failed to publish AGENT_ERROR to outbound queue — " +
                    "cert will remain stuck in current status until manually resolved. " +
                    "xref={}, organizationId={}, errorCode={}, cause={}",
                    certificateXref, organizationId, errorCode, ex.getMessage());
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
