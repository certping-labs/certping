// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.CaOrderPendingException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.SslIssuanceService;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.listener.ScheduledRetryService;
import com.certping.agent.ssl.dns.DnsPropagationVerifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;

/**
 * Handles CERT_ISSUANCE commands from this organization's inbound queue.
 *
 * Flow:
 *   1. Receive CERT_ISSUANCE from {orgId}-agent-inbound through the agent gateway
 *   2. Read DNS credential from the secret store using dnsCredentialHandle (via SslIssuanceService)
 *   3. Perform ACME / DigiCert / GlobalSign issuance
 *   4. Store cert PEM in the secret store at certSecretHandle
 *   5. Send CERT_ISSUANCE_RESPONSE to cert-agent-outbound
 *   6. The server receives response, updates DB, publishes CERT_ISSUANCE_SUCCESS to the notifications queue
 *
 * certping-agent does NOT publish to the notifications queue — that is the server's responsibility.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertIssuanceProcessor {

    private final SslIssuanceService sslIssuanceService;
    private final ScheduledRetryService scheduledRetryService;
    private final StoredResultPublisher storedResultPublisher;
    private final AttemptRecords attemptRecords;
    private final Clock clock;

    public void process(CertIssuanceMessage message, InboundContext context) {
        AttemptRecords.Resume resume = attemptRecords.resume(context.getMessage(), message.getCertificateXref());
        if (storedResultPublisher.finishEnded(context, message.getCertificateXref(), resume)) {
            return;
        }
        resume.checkpoint().ifPresent(message::setCheckpoint);
        message.setCheckpointRecorder(attemptRecords.recorder(context.getMessage(), message.getCertificateXref(),
                resume.checkpoint()));
        message.setFinalPropagationWait(scheduledRetryService.retriesUsedUp(context.getMessage(),
                DnsPropagationVerifier.PROPAGATION_PENDING));
        scheduledRetryService.requireTimeLeft(context.getMessage());
        message.setAttemptDeadline(scheduledRetryService.attemptDeadline(context.getMessage()));
        message.setAttemptKey(ScheduledRetryService.attemptKey(context.getMessage()).orElse(null));

        log.info("Processing CERT_ISSUANCE — domain={}, caProvider={}, xref={}, resumeStep={}",
                message.getDomain(), message.getCaProvider(), message.getCertificateXref(),
                message.getCheckpoint() == null ? "none" : message.getCheckpoint().step());

        IssuanceResult result;
        try {
            result = sslIssuanceService.issue(message);
        } catch (CaOrderPendingException e) {
            log.info("CERT_ISSUANCE waiting on the CA: domain={}, provider={}, orderRef={}, nextCheckSec={}",
                    message.getDomain(), e.getProvider(), e.getOrderRef(), e.getRetryAfter().toSeconds());
            throw e;
        } catch (Exception e) {
            log.error("CERT_ISSUANCE failed: domain={}, error={}", message.getDomain(), e.getMessage(), e);
            throw e instanceof RuntimeException re
                    ? DnsPropagationVerifier.retryUnlessFinal(re, message.isFinalPropagationWait())
                    : new PermanentAgentException("ISSUANCE_FAILED", e.getMessage(), e);
        }

        storedResultPublisher.publish(IssuanceResponses.of(message.getRequestId(), message.getCorrelationId(),
                message.getOrganizationId(), message.getCertificateXref(), IssuanceResponses.ISSUED,
                message.getCaProvider(), result, clock), context);
    }
}
