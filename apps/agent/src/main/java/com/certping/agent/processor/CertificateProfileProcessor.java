// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.CertificateProfileMessage;
import com.certping.agent.model.message.CertificateProfileResponse;
import com.certping.agent.model.message.ProfileObservedState;
import com.certping.agent.platform.CertificateProfileConnector;
import com.certping.agent.platform.CertificateProfileConnectorFactory;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Locale;

@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateProfileProcessor {
    private final CertificateProfileConnectorFactory connectorFactory;
    private final DeviceSourceProfileRegistry sourceProfileRegistry;
    private final AgentMessageSender sender;
    private final Clock clock;

    public void process(
            CertificateProfileMessage message, InboundContext context) {
        validate(message);
        boolean mutationSucceeded = false;
        try {
            DevicePlatformType provider = DevicePlatformType.fromString(message.getProvider());
            DeviceSourceProfile source = sourceProfileRegistry.require(
                    message.getConnectionProfileRef(), provider);
            CertificateProfileConnector connector = connectorFactory.create(provider);
            ProfileObservedState observed = switch (
                    message.getOperation().toUpperCase(Locale.ROOT)) {
                case "CREATE" -> connector.create(source, message);
                case "UPDATE" -> connector.update(source, message);
                default -> throw new PermanentAgentException("PROFILE_OPERATION_UNSUPPORTED",
                        "Profile operation must be CREATE or UPDATE");
            };
            mutationSucceeded = true;
            sender.sendCertificateProfileResponse(response(message)
                    .status("SUCCEEDED")
                    .profile(observed)
                    .respondedAt(now())
                    .build());
            context.complete();
        } catch (RetryableAgentException | TransientAgentException exception) {
            if (mutationSucceeded) {
                throw responseDeliveryFailure(message, exception);
            }
            throw exception;
        } catch (Exception exception) {
            if (mutationSucceeded) {
                throw responseDeliveryFailure(message, exception);
            }
            String errorCode = exception instanceof AgentException agentException
                    ? agentException.getErrorCode() : "PROFILE_OPERATION_FAILED";
            log.error("Certificate-profile operation failed: source={} profile={} operation={} code={}",
                    message.getSourceXref(), message.getProfileXref(),
                    message.getOperation(), errorCode);
            sender.sendCertificateProfileResponse(response(message)
                    .status("FAILED")
                    .errorCode(errorCode)
                    .errorMessage(safeMessage(exception,
                            "Certificate profile operation failed"))
                    .respondedAt(now())
                    .build());
            context.complete();
        }
    }

    private CertificateProfileResponse.CertificateProfileResponseBuilder response(
            CertificateProfileMessage message) {
        return CertificateProfileResponse.builder()
                .requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .sourceXref(message.getSourceXref())
                .profileXref(message.getProfileXref())
                .operationXref(message.getOperationXref())
                .desiredRevision(message.getDesiredRevision());
    }

    private String now() {
        return OffsetDateTime.now(clock).toString();
    }

    private static void validate(CertificateProfileMessage message) {
        if (blank(message.getRequestId()) || blank(message.getOrganizationId())
                || blank(message.getSourceXref()) || blank(message.getConnectionProfileRef())
                || blank(message.getProfileXref()) || blank(message.getOperationXref())
                || blank(message.getProvider()) || blank(message.getOperation())
                || message.getDesiredRevision() == null
                || message.getDesiredRevision() < 1) {
            throw new PermanentAgentException("INVALID_PROFILE_COMMAND",
                    "requestId, organizationId, source, local profile, profileXref, operationXref, "
                            + "provider, operation and revision are required");
        }
    }

    private static String safeMessage(Exception exception, String fallback) {
        String value = exception instanceof AgentException ? exception.getMessage() : fallback;
        if (value == null || value.isBlank()) value = fallback;
        return value.length() <= 1000 ? value : value.substring(0, 1000);
    }

    private static PermanentAgentException responseDeliveryFailure(
            CertificateProfileMessage message, Exception cause) {
        log.error("Certificate-profile response delivery is uncertain after successful mutation: "
                        + "source={} profile={} operation={}",
                message.getSourceXref(), message.getProfileXref(), message.getOperation());
        return new PermanentAgentException("PROFILE_RESPONSE_DELIVERY_FAILED",
                "Profile mutation succeeded but response delivery could not be confirmed",
                cause);
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
