// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.transport.DeadLetterOptions;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.model.message.CertIssuanceResponse;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Optional;

/**
 * Sends the result of a certificate the agent has issued and stored. The result is recorded with the certificate
 * first ({@link AttemptRecords}) and stays recorded, so any later delivery of the attempt only sends it again, and
 * the server ignores the duplicate. A result that cannot be sent stays on the agent's own queue (checkpoint
 * {@link IssuanceCheckpoint.Step#KV_STORED}) and the next attempt only sends it again, so the certificate is not
 * ordered a second time. A result still unsent at the attempt deadline is dead-lettered for a manual replay, and
 * the server ends the attempt once its own horizon passes.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StoredResultPublisher {

    public static final String PUBLISH_FAILED = "RESPONSE_PUBLISH_FAILED";
    static final String REPLAY_MISMATCH = "RESPONSE_REPLAY_MISMATCH";
    static final String REPLAY_MISMATCH_METRIC = "agent.response.replay.mismatch.count";

    private final AgentMessageSender sender;
    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final MeterRegistry meterRegistry;
    private final AttemptRecords attemptRecords;

    /**
     * Records {@code response}, the result of a certificate just stored, then sends it and settles the message. It
     * is not sent unrecorded: a redelivery after the send would issue the certificate again.
     *
     * @throws RetryableAgentException {@link #PUBLISH_FAILED} carrying {@code response} when it cannot be recorded
     *                                 or sent
     */
    public void publish(CertIssuanceResponse response, InboundContext context) {
        IssuanceCheckpoint stored = IssuanceCheckpoint.storedResult(providerName(response), serialize(response));
        try {
            attemptRecords.save(context.getMessage(), response.getCertificateXref(), stored);
        } catch (RuntimeException e) {
            log.warn("Result of xref={} not recorded, so not sent; kept for the next attempt: {}",
                    response.getCertificateXref(), e.getMessage());
            throw new RetryableAgentException(PUBLISH_FAILED, "The certificate is stored but its result was not sent",
                    null, e, stored);
        }
        send(response, stored, context);
    }

    private void send(CertIssuanceResponse response, IssuanceCheckpoint stored,
                      InboundContext context) {
        try {
            sender.sendIssuanceResponse(response);
        } catch (TransientAgentException e) {
            log.warn("Result of xref={} not sent; kept for the next attempt: {}",
                    response.getCertificateXref(), e.getMessage());
            throw new RetryableAgentException(PUBLISH_FAILED, "The certificate is stored but its result was not sent",
                    null, e, stored);
        }
        log.info("CERT_ISSUANCE_RESPONSE sent: xref={}, status={}", response.getCertificateXref(),
                response.getStatus());
        try {
            context.complete();
        } catch (RuntimeException e) {
            log.warn("Result of xref={} sent but the message was not settled; its redelivery sends it again: {}",
                    response.getCertificateXref(), e.getMessage());
        }
    }

    /**
     * Finishes a delivery of an attempt that already ended: a failed attempt is settled and nothing is done, and a
     * stored result is sent again after checking it against the certificate in this agent's store. A result that does
     * not match it is dead-lettered without an {@code AGENT_ERROR}: the certificate may well exist (the same xref
     * issued again, for one), and an error would mark it failed.
     *
     * @return whether the attempt had ended, so there is nothing left to do
     */
    public boolean finishEnded(InboundContext context, String certificateXref,
                               AttemptRecords.Resume resume) {
        if (resume.failed()) {
            log.info("The attempt of xref={} already failed and was dead-lettered; settling this delivery",
                    certificateXref);
            try {
                context.complete();
            } catch (RuntimeException e) {
                log.warn("Delivery of the failed attempt of xref={} not settled: {}", certificateXref, e.getMessage());
            }
            return true;
        }
        Optional<IssuanceCheckpoint> stored = resume.checkpoint()
                .filter(resumed -> resumed.step() == IssuanceCheckpoint.Step.KV_STORED);
        if (stored.isEmpty()) {
            return false;
        }
        CertIssuanceResponse response;
        try {
            response = verified(stored.get(), certificateXref);
        } catch (PermanentAgentException e) {
            deadLetterMismatch(context, certificateXref, e.getMessage());
            return true;
        }
        log.info("Sending the stored result of xref={} again", certificateXref);
        send(response, stored.get(), context);
        return true;
    }

    /**
     * The stored result for {@code certificateXref}, with what the certificate itself says (serial, validity,
     * fingerprint) taken from the stored certificate rather than from the result.
     */
    private CertIssuanceResponse verified(IssuanceCheckpoint stored, String certificateXref) {
        CertIssuanceResponse response = parse(stored.response());
        if (!certificateXref.equals(response.getCertificateXref())) {
            throw mismatch("it answers xref=" + response.getCertificateXref() + ", not xref=" + certificateXref);
        }
        String handle = response.getCertSecretHandle();
        if (handle == null || !secretStore.isOwnedByThisAgent(handle)) {
            throw mismatch("its certificate is not in this agent's store");
        }
        X509Certificate leaf = storedLeaf(handle, stored);
        String fingerprint = fingerprint(leaf);
        if (!fingerprint.equalsIgnoreCase(response.getFingerprintSha256())) {
            throw mismatch("the stored certificate has another fingerprint");
        }
        response.setFingerprintSha256(fingerprint);
        response.setSerialNumber(leaf.getSerialNumber().toString(16).toUpperCase(Locale.ROOT));
        response.setValidFrom(leaf.getNotBefore().toInstant().atOffset(ZoneOffset.UTC).toString());
        response.setValidTo(leaf.getNotAfter().toInstant().atOffset(ZoneOffset.UTC).toString());
        return response;
    }

    /** A store that cannot be read right now keeps the result for the next attempt; a missing one cannot match. */
    private X509Certificate storedLeaf(String handle, IssuanceCheckpoint stored) {
        String bundle;
        try {
            bundle = secretStore.read(handle);
        } catch (TransientAgentException | RetryableAgentException e) {
            throw new RetryableAgentException(e.getErrorCode(), e.getMessage(), null, e, stored);
        } catch (PermanentAgentException e) {
            throw mismatch("the stored certificate is gone: " + e.getErrorCode());
        }
        try {
            return CertificateMetadataExtractor.firstCertificate(bundle);
        } catch (CertificateException e) {
            throw mismatch("the stored certificate cannot be read: " + e.getMessage());
        }
    }

    private static String fingerprint(X509Certificate leaf) {
        try {
            return CertificateMetadataExtractor.sha256Fingerprint(leaf);
        } catch (CertificateEncodingException e) {
            throw mismatch("the stored certificate cannot be encoded: " + e.getMessage());
        }
    }

    private void deadLetterMismatch(InboundContext context, String certificateXref, String reason) {
        log.error("[{}] xref={}: {}; dead-lettered without an AGENT_ERROR", REPLAY_MISMATCH, certificateXref, reason);
        meterRegistry.counter(REPLAY_MISMATCH_METRIC).increment();
        attemptRecords.fail(context.getMessage(), certificateXref);
        try {
            context.deadLetter(new DeadLetterOptions()
                    .setDeadLetterReason(REPLAY_MISMATCH)
                    .setDeadLetterErrorDescription(reason));
        } catch (RuntimeException settleError) {
            log.error("Failed to dead-letter {} message — will redeliver until max-delivery-count: {}",
                    REPLAY_MISMATCH, settleError.getMessage());
        }
    }

    private CertIssuanceResponse parse(String json) {
        if (json == null) {
            throw mismatch("no result was stored");
        }
        try {
            return objectMapper.readValue(json, CertIssuanceResponse.class);
        } catch (JacksonException e) {
            throw mismatch("the stored result is not a CERT_ISSUANCE_RESPONSE");
        }
    }

    private String serialize(CertIssuanceResponse response) {
        try {
            return objectMapper.writeValueAsString(response);
        } catch (JacksonException e) {
            throw new PermanentAgentException("SERIALIZATION_FAILED",
                    "Failed to serialize CERT_ISSUANCE_RESPONSE: " + e.getMessage(), e);
        }
    }

    private static String providerName(CertIssuanceResponse response) {
        return response.getCaProvider() == null ? null : response.getCaProvider().name();
    }

    private static PermanentAgentException mismatch(String reason) {
        return new PermanentAgentException(REPLAY_MISMATCH, "Stored result not sent: " + reason);
    }
}
