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
import com.certping.agent.model.message.IotDeviceSyncMessage;
import com.certping.agent.model.message.IotDeviceSyncResponse;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.platform.intune.IntuneGraphClient;
import com.certping.agent.platform.intune.IntuneSession;
import com.certping.agent.platform.intune.IntuneSessionProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Executes one best-effort Intune {@code syncDevice} action and reports its outcome.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IotDeviceSyncProcessor {

    private final DeviceSourceProfileRegistry profileRegistry;
    private final IntuneSessionProvider sessionProvider;
    private final IntuneGraphClient graphClient;
    private final AgentMessageSender sender;
    private final Clock clock;

    public void process(IotDeviceSyncMessage message, InboundContext context) {
        validateEnvelope(message);

        String outcome;
        Integer httpStatus = null;
        String errorCode = null;
        String errorMessage = null;
        try {
            validateOperation(message);
            DevicePlatformType provider = DevicePlatformType.fromString(message.getProvider());
            if (provider != DevicePlatformType.INTUNE) {
                outcome = "SKIPPED_UNSUPPORTED";
                errorCode = "UNSUPPORTED_PROVIDER";
            } else {
                DeviceSourceProfile profile = profileRegistry.require(
                        message.getConnectionProfileRef(), provider);
                IntuneSession session = sessionProvider.open(profile);
                graphClient.syncDevice(session.token(), message.getManagedDeviceId());
                outcome = "NUDGE_SENT";
                httpStatus = 204;
                log.info("Intune syncDevice sent org={} source={} device={} certificateCount={}",
                        message.getOrganizationId(), message.getSourceXref(), message.getDeviceXref(),
                        message.getCertificateXrefs().size());
            }
        } catch (PermanentAgentException e) {
            outcome = "INTUNE_REJECTED";
            errorCode = e.getErrorCode();
            errorMessage = e.getMessage();
            httpStatus = httpStatus(e);
            log.warn("Intune syncDevice rejected org={} source={} code={}",
                    message.getOrganizationId(), message.getSourceXref(), errorCode);
        } catch (TransientAgentException | RetryableAgentException e) {
            outcome = "INTUNE_UNAVAILABLE";
            errorCode = ((AgentException) e).getErrorCode();
            errorMessage = e.getMessage();
            httpStatus = httpStatus((AgentException) e);
            log.warn("Intune syncDevice unavailable org={} source={} code={}",
                    message.getOrganizationId(), message.getSourceXref(), errorCode);
        }

        sender.sendIotDeviceSyncResponse(IotDeviceSyncResponse.builder()
                .requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .sourceXref(message.getSourceXref())
                .deviceXref(message.getDeviceXref())
                .certificateXrefs(message.getCertificateXrefs())
                .managedDeviceId(message.getManagedDeviceId())
                .outcome(outcome)
                .httpStatus(httpStatus)
                .errorCode(errorCode)
                .errorMessage(bounded(errorMessage))
                .respondedAt(OffsetDateTime.now(clock).toString())
                .build());
        context.complete();
    }

    private static void validateEnvelope(IotDeviceSyncMessage message) {
        if (message == null || blank(message.getRequestId()) || blank(message.getOrganizationId())
                || blank(message.getDeviceXref()) || invalidCertificateXrefs(message.getCertificateXrefs())) {
            throw new PermanentAgentException("INVALID_SYNC_COMMAND",
                    "requestId, organizationId, deviceXref and certificateXrefs are required");
        }
    }

    private static void validateOperation(IotDeviceSyncMessage message) {
        if (message.getConnectionProfileRef() == null || message.getConnectionProfileRef().isBlank()
                || message.getProvider() == null || message.getProvider().isBlank()
                || message.getManagedDeviceId() == null || message.getManagedDeviceId().isBlank()) {
            throw new PermanentAgentException("INVALID_SYNC_COMMAND",
                    "provider, connectionProfileRef and managedDeviceId are required");
        }
    }

    private static boolean invalidCertificateXrefs(List<String> values) {
        if (values == null || values.isEmpty() || values.size() > 100) {
            return true;
        }
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        for (String value : values) {
            if (blank(value) || value.length() > 100 || !unique.add(value)) {
                return true;
            }
        }
        return false;
    }

    private static Integer httpStatus(AgentException exception) {
        Throwable current = exception;
        while (current != null) {
            if (current instanceof org.springframework.web.client.HttpStatusCodeException statusException) {
                return statusException.getStatusCode().value();
            }
            current = current.getCause();
        }
        return null;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String bounded(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= 255 ? value : value.substring(0, 255);
    }
}
