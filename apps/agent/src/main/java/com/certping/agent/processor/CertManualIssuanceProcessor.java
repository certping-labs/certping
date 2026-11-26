// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.transport.DeadLetterOptions;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.listener.ScheduledRetryService;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertManualTxtRequestMessage;
import com.certping.agent.model.message.CertManualTxtResponse;
import com.certping.agent.model.message.CertManualValidateMessage;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.acme.LetsEncryptManualService;
import com.certping.agent.ssl.acme.ManualTxtResult;
import com.certping.agent.ssl.dns.DnsPropagationVerifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Slf4j
@Component
@RequiredArgsConstructor
public class CertManualIssuanceProcessor {

    private final LetsEncryptManualService letsEncryptManualService;
    private final AgentMessageSender sender;
    private final StoredResultPublisher storedResultPublisher;
    private final AttemptRecords attemptRecords;
    private final ScheduledRetryService scheduledRetryService;
    private final Clock clock;

    /** Handles {@code CERT_MANUAL_TXT_REQUEST}: ACME order + DNS-01 TXT values, then {@code CERT_MANUAL_TXT_RESPONSE}. */
    public void processManualTxtRequest(CertManualTxtRequestMessage msg, InboundContext ctx) {
        log.info("CERT_MANUAL_TXT_REQUEST — domain={}, xref={}", msg.getDomain(), msg.getCertificateXref());

        if (msg.getOrganizationId() == null || msg.getOrganizationId().isBlank()) {
            throw new PermanentAgentException("MANUAL_TXT_REQUEST_INVALID", "organizationId is required");
        }
        if (msg.getCertificateXref() == null || msg.getCertificateXref().isBlank()) {
            throw new PermanentAgentException("MANUAL_TXT_REQUEST_INVALID", "certificateXref is required");
        }
        if (msg.getDomain() == null || msg.getDomain().isBlank()) {
            throw new PermanentAgentException("MANUAL_TXT_REQUEST_INVALID", "domain is required");
        }
        if (msg.getCaProvider() == null || msg.getCaProvider() != CaProvider.LETS_ENCRYPT) {
            throw new PermanentAgentException("UNSUPPORTED_CA_FOR_MANUAL",
                    "Manual issuance only supports LETS_ENCRYPT; got: " + msg.getCaProvider());
        }

        ManualTxtResult result = letsEncryptManualService.requestTxtRecords(
                msg.getOrganizationId(),
                msg.getCertificateXref(),
                msg.getDomain(),
                msg.isWildcard(),
                msg.isSan(),
                msg.getSanDomainEntries(),
                msg.getAcmeAccountHandle());

        CertManualTxtResponse response = CertManualTxtResponse.builder()
                .requestId(msg.getRequestId())
                .correlationId(msg.getCorrelationId())
                .organizationId(msg.getOrganizationId())
                .certificateXref(msg.getCertificateXref())
                .txtRecords(result.txtRecords())
                .acmeOrderUrl(result.orderUrl().toString())
                .acmeAccountHandle(result.acmeAccountHandle())
                .respondedAt(OffsetDateTime.now(ZoneOffset.UTC).toString())
                .build();

        try {
            sender.sendManualTxtResponse(response);
            ctx.complete();
            log.info("CERT_MANUAL_TXT_RESPONSE sent: xref={}", msg.getCertificateXref());
        } catch (Exception e) {
            log.error("CRITICAL: ACME order created but CERT_MANUAL_TXT_RESPONSE publish failed. " +
                      "xref={}, orderUrl={}, error={}. " +
                      "Dead-lettering to prevent duplicate ACME order on re-delivery — manual recovery required.",
                      msg.getCertificateXref(), result.orderUrl(), e.getMessage(), e);
            ctx.deadLetter(new DeadLetterOptions()
                    .setDeadLetterReason("MANUAL_TXT_RESPONSE_PUBLISH_FAILED")
                    .setDeadLetterErrorDescription(
                            "ACME order created at " + result.orderUrl() +
                            " but CERT_MANUAL_TXT_RESPONSE could not be sent to the server: " + e.getMessage()));
        }
    }

    /** Handles {@code CERT_MANUAL_DNS_VALIDATE}: authoritative DNS check, ACME finalize, KV store, then {@code CERT_ISSUANCE_RESPONSE}. */
    public void processManualDnsValidation(CertManualValidateMessage msg, InboundContext ctx) {
        if (storedResultPublisher.finishEnded(ctx, msg.getCertificateXref(),
                attemptRecords.resume(ctx.getMessage(), msg.getCertificateXref()))) {
            return;
        }
        scheduledRetryService.requireTimeLeft(ctx.getMessage());
        log.info("CERT_MANUAL_DNS_VALIDATE — domain={}, xref={}", msg.getDomain(), msg.getCertificateXref());

        if (msg.getCaProvider() == null || msg.getCaProvider() != CaProvider.LETS_ENCRYPT) {
            throw new PermanentAgentException("UNSUPPORTED_CA_FOR_MANUAL",
                    "Manual issuance only supports LETS_ENCRYPT; got: " + msg.getCaProvider());
        }

        boolean finalWait = scheduledRetryService.retriesUsedUp(ctx.getMessage(),
                DnsPropagationVerifier.PROPAGATION_PENDING);
        IssuanceResult result;
        try {
            result = letsEncryptManualService.completeValidation(
                    msg.getOrganizationId(),
                    msg.getCertificateXref(),
                    msg.getDomain(),
                    msg.isWildcard(),
                    msg.isSan(),
                    msg.getSanDomainEntries(),
                    msg.getAcmeOrderUrl(),
                    msg.getAcmeAccountHandle(),
                    msg.getTxtRecords());
        } catch (RuntimeException e) {
            throw DnsPropagationVerifier.retryUnlessFinal(e, finalWait);
        }

        storedResultPublisher.publish(IssuanceResponses.of(msg.getRequestId(), msg.getCorrelationId(),
                msg.getOrganizationId(), msg.getCertificateXref(), IssuanceResponses.ISSUED, CaProvider.LETS_ENCRYPT,
                result, clock), ctx);
    }
}
