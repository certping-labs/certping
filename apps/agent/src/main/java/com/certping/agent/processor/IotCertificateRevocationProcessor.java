// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.IotCertificateRevocationMessage;
import com.certping.agent.model.message.IotCertificateRevocationResponse;
import com.certping.agent.ssl.ejbca.EjbcaRevocationService;
import com.certping.agent.ssl.smallstep.SmallstepRevocationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class IotCertificateRevocationProcessor {
    private final EjbcaRevocationService ejbcaRevocationService;
    private final SmallstepRevocationService smallstepRevocationService;
    private final AgentMessageSender sender;

    public void process(IotCertificateRevocationMessage message,
                        InboundContext context) {
        try {
            validate(message);
            Result result = revoke(message);
            // operation= is the server's key for this revocation; without it the agent side of
            // a revocation was entirely silent and only the CA knew what happened.
            log.info("IoT certificate revocation confirmed: operation={} certificate={} ca={} "
                            + "serial={} reason={} caObservedReason={}",
                    message.getOperationXref(), message.getCertificateXref(),
                    message.getCaProvider(), message.getSerialNumber(), message.getReason(),
                    result.reason());
            sender.sendIotCertificateRevocationResponse(response(message, "CONFIRMED",
                    result.reason(), result.observedAt(), null, null));
            context.complete();
        } catch (PermanentAgentException exception) {
            // The error code only: CA error bodies can echo the requested subject.
            log.warn("IoT certificate revocation failed: operation={} certificate={} ca={} code={}",
                    message.getOperationXref(), message.getCertificateXref(),
                    message.getCaProvider(), exception.getErrorCode());
            sender.sendIotCertificateRevocationResponse(response(message, "FAILED",
                    null, null, exception.getErrorCode(), exception.getMessage()));
            context.complete();
        }
    }

    private static void validate(IotCertificateRevocationMessage message) {
        if (message == null || blank(message.getOperationXref())
                || blank(message.getCertificateXref()) || blank(message.getIssuerDn())
                || blank(message.getSerialNumber()) || blank(message.getReason())
                || message.getDispatchAttempt() == null || message.getDispatchAttempt() < 1
                || !validRequestId(message)) {
            throw new PermanentAgentException("IOT_REVOCATION_COMMAND_INVALID",
                    "IoT revocation command is missing required fields");
        }
        if (!"EJBCA".equalsIgnoreCase(message.getCaProvider())
                && !"SMALLSTEP".equalsIgnoreCase(message.getCaProvider())) {
            throw new PermanentAgentException("IOT_CA_REVOCATION_UNSUPPORTED",
                    "The certificate authority provider does not support IoT revocation");
        }
    }

    private static boolean validRequestId(IotCertificateRevocationMessage message) {
        String simple = message.getOperationXref() + ":" + message.getDispatchAttempt();
        if (simple.equals(message.getRequestId())) return true;
        String prefix = message.getOperationXref() + ":";
        String suffix = ":" + message.getDispatchAttempt();
        String requestId = message.getRequestId();
        if (blank(requestId) || !requestId.startsWith(prefix) || !requestId.endsWith(suffix)) {
            return false;
        }
        int start = prefix.length();
        int end = requestId.length() - suffix.length();
        return end > start && !requestId.substring(start, end).isBlank();
    }

    private Result revoke(IotCertificateRevocationMessage message) {
        if ("EJBCA".equalsIgnoreCase(message.getCaProvider())) {
            EjbcaRevocationService.Result result = ejbcaRevocationService.revoke(
                    message.getIssuerDn(), message.getSerialNumber(), message.getReason());
            return new Result(result.reason(), result.observedAt());
        }
        SmallstepRevocationService.Result result = smallstepRevocationService.revoke(
                message.getIssuerDn(), message.getSerialNumber(), message.getReason());
        return new Result(result.reason(), result.observedAt());
    }

    private static IotCertificateRevocationResponse response(
            IotCertificateRevocationMessage message, String outcome,
            String observedReason, String observedAt, String errorCode, String errorMessage) {
        return IotCertificateRevocationResponse.builder()
                .messageVersion(1)
                .requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .operationXref(message.getOperationXref())
                .dispatchAttempt(message.getDispatchAttempt())
                .certificateXref(message.getCertificateXref())
                .outcome(outcome)
                .reason(message.getReason())
                .caObservedReason(observedReason)
                .observedAt(observedAt)
                .errorCode(errorCode)
                .errorMessage(errorMessage)
                .build();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private record Result(String reason, String observedAt) {}
}
