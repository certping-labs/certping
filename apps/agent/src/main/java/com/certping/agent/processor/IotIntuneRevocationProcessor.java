// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.listener.ScheduledRetryService;
import com.certping.agent.model.message.IotIntuneRevocationPollMessage;
import com.certping.agent.model.message.IotIntuneRevocationPollResponse;
import com.certping.agent.model.message.IotIntuneRevocationUploadMessage;
import com.certping.agent.model.message.IotIntuneRevocationUploadResponse;
import com.certping.agent.platform.intune.IntuneRevocationClient;
import com.certping.agent.platform.intune.IntuneRevocationReplayCache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class IotIntuneRevocationProcessor {
    private final IntuneRevocationClient client;
    private final IntuneRevocationReplayCache replayCache;
    private final AgentMessageSender sender;

    public void poll(IotIntuneRevocationPollMessage message,
                     InboundContext context) {
        validatePoll(message);
        List<IntuneRevocationClient.RevocationRequest> requests;
        try {
            requests = replayCache.download(
                    message.getConnectionProfileRef(), message.getTransactionId(),
                    () -> client.download(message.getConnectionProfileRef(),
                            message.getTransactionId(), message.getMaxRequests()));
            validateDownloaded(requests, message.getMaxRequests());
        } catch (PermanentAgentException | TransientAgentException exception) {
            log.warn("Intune revocation poll failed: source={} txn={} attempt={} code={}",
                    message.getSourceXref(), message.getTransactionId(),
                    message.getDispatchAttempt(), exception.getErrorCode());
            sender.sendIotIntuneRevocationPollResponse(pollResponse(
                    message, context, "FAILED", List.of(), exception.getErrorCode(),
                    exception.getMessage()));
            context.complete();
            return;
        }
        // Only the count: each downloaded request carries an opaque Intune context that embeds the
        // serial and issuer of the device's certificate.
        log.info("Intune revocation poll completed: source={} txn={} requests={} attempt={}",
                message.getSourceXref(), message.getTransactionId(), requests.size(),
                message.getDispatchAttempt());
        sender.sendIotIntuneRevocationPollResponse(pollResponse(
                message, context, "SUCCESS", requests, null, null));
        context.complete();
    }

    public void upload(IotIntuneRevocationUploadMessage message,
                       InboundContext context) {
        validateUpload(message);
        boolean replayed = replayCache.wasUploaded(
                message.getConnectionProfileRef(), message.getTransactionId());
        try {
            if (!replayed) {
                client.upload(message.getConnectionProfileRef(), message.getTransactionId(),
                        message.getResults());
                replayCache.markUploaded(
                        message.getConnectionProfileRef(), message.getTransactionId());
            }
        } catch (PermanentAgentException | TransientAgentException exception) {
            log.warn("Intune revocation upload failed: source={} txn={} attempt={} code={}",
                    message.getSourceXref(), message.getTransactionId(),
                    message.getDispatchAttempt(), exception.getErrorCode());
            sender.sendIotIntuneRevocationUploadResponse(uploadResponse(
                    message, "FAILED", exception.getErrorCode(), exception.getMessage()));
            context.complete();
            return;
        }
        // replayed= distinguishes "uploaded now" from "already uploaded, skipped", which was
        // indistinguishable before and is the first thing asked when results look missing.
        log.info("Intune revocation upload completed: source={} txn={} results={} attempt={} "
                        + "replayed={}",
                message.getSourceXref(), message.getTransactionId(), message.getResults().size(),
                message.getDispatchAttempt(), replayed);
        sender.sendIotIntuneRevocationUploadResponse(uploadResponse(
                message, "SUCCESS", null, null));
        context.complete();
    }

    private static void validatePoll(IotIntuneRevocationPollMessage message) {
        if (message == null || blank(message.getConnectionProfileRef())
                || blank(message.getSourceXref()) || blank(message.getTransactionId())
                || message.getMaxRequests() == null || message.getDispatchAttempt() == null
                || message.getDispatchAttempt() < 1
                || !expectedRequestId(message.getTransactionId(), "poll",
                        message.getDispatchAttempt()).equals(message.getRequestId())) {
            throw new PermanentAgentException("INTUNE_REVOCATION_POLL_INVALID",
                    "Intune revocation poll command is missing required fields");
        }
    }

    private static void validateUpload(IotIntuneRevocationUploadMessage message) {
        if (message == null || blank(message.getConnectionProfileRef())
                || blank(message.getSourceXref()) || blank(message.getTransactionId())
                || message.getResults() == null || message.getResults().isEmpty()
                || message.getDispatchAttempt() == null || message.getDispatchAttempt() < 1
                || !expectedRequestId(message.getTransactionId(), "upload",
                        message.getDispatchAttempt()).equals(message.getRequestId())) {
            throw new PermanentAgentException("INTUNE_REVOCATION_UPLOAD_INVALID",
                    "Intune revocation upload command is missing required fields");
        }
    }

    private static IotIntuneRevocationPollResponse pollResponse(
            IotIntuneRevocationPollMessage message,
            InboundContext context, String outcome,
            List<IntuneRevocationClient.RevocationRequest> requests,
            String errorCode, String errorMessage) {
        return IotIntuneRevocationPollResponse.builder()
                .messageVersion(1).requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .sourceXref(message.getSourceXref())
                .transactionId(message.getTransactionId())
                .dispatchAttempt(message.getDispatchAttempt())
                .redelivered(ScheduledRetryService.currentRetryCount(context.getMessage()) > 0
                        || context.getMessage().getDeliveryCount() > 0)
                .outcome(outcome)
                .requests(requests).errorCode(errorCode).errorMessage(errorMessage).build();
    }

    private static IotIntuneRevocationUploadResponse uploadResponse(
            IotIntuneRevocationUploadMessage message, String outcome,
            String errorCode, String errorMessage) {
        return IotIntuneRevocationUploadResponse.builder()
                .messageVersion(1).requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .sourceXref(message.getSourceXref())
                .transactionId(message.getTransactionId())
                .dispatchAttempt(message.getDispatchAttempt()).outcome(outcome)
                .errorCode(errorCode).errorMessage(errorMessage).build();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String expectedRequestId(String transactionId, String operation, int attempt) {
        return transactionId + ":" + operation + ":" + attempt;
    }

    private static void validateDownloaded(
            List<IntuneRevocationClient.RevocationRequest> requests, int maxRequests) {
        if (requests == null || requests.size() > maxRequests) {
            throw new PermanentAgentException("INTUNE_REVOCATION_RESPONSE_INVALID",
                    "Intune returned an invalid revocation request count");
        }
        for (IntuneRevocationClient.RevocationRequest request : requests) {
            if (request == null || tooLong(request.requestContext(), 1000)
                    || tooLong(request.serialNumber(), 160)
                    || tooLong(request.issuerName(), 2000)) {
                throw new PermanentAgentException("INTUNE_REVOCATION_RESPONSE_INVALID",
                        "Intune returned an invalid revocation request");
            }
        }
    }

    private static boolean tooLong(String value, int maximum) {
        return value == null || value.isBlank() || value.length() > maximum;
    }
}
