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
import com.certping.agent.model.message.DeviceIdentityEntry;
import com.certping.agent.model.message.DeviceIdentitySyncCompleteMessage;
import com.certping.agent.model.message.DeviceIdentitySyncMessage;
import com.certping.agent.model.message.DeviceIdentitySyncResponse;
import com.certping.agent.platform.DeviceIdentityConnector;
import com.certping.agent.platform.DeviceIdentityConnectorFactory;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.platform.DeviceSourceProperties;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** Runs a full device sync only when the server delivers an explicit command. */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeviceIdentitySyncProcessor {
    static final int BATCH_SIZE = 50;

    private final DeviceIdentityConnectorFactory connectorFactory;
    private final DeviceSourceProfileRegistry profileRegistry;
    private final DeviceSourceProperties sourceProperties;
    private final AgentMessageSender sender;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public void process(DeviceIdentitySyncMessage message, InboundContext context) {
        validate(message);
        DevicePlatformType provider = DevicePlatformType.fromString(message.getProvider());
        DeviceSourceProfile profile = profileRegistry.require(
                message.getConnectionProfileRef(), provider);
        DeviceIdentityConnector connector = connectorFactory.create(provider);

        log.info("Processing device-source sync: source={} org={} provider={} profile={} sync={}",
                message.getSourceXref(), message.getOrganizationId(), provider,
                profile.profileRef(), message.getSyncXref());
        // Declared outside the try so a failure can say how far the run got: the server is
        // holding whatever batches did arrive under this syncXref, and "failed" alone does not
        // tell the operator whether that is none of them or almost all.
        Counters counters = new Counters();
        try {
            List<DeviceIdentityEntry> buffer = new ArrayList<>(BATCH_SIZE);
            connector.streamDevices(profile, page -> appendPage(message, page, buffer, counters));
            if (!buffer.isEmpty()) {
                sendBatch(message, counters.batchIndex++, List.copyOf(buffer));
            }
            sendComplete(message, counters.total, counters.batchIndex);
            context.complete();
        } catch (Exception exception) {
            String errorCode = exception instanceof AgentException agentException
                    ? agentException.getErrorCode() : "SYNC_FAILED";
            log.error("Device-source sync failed: source={} org={} provider={} sync={} code={} "
                            + "devicesSent={} batchesSent={}",
                    message.getSourceXref(), message.getOrganizationId(), message.getProvider(),
                    message.getSyncXref(), errorCode, counters.total, counters.batchIndex);
            if (exception instanceof TransientAgentException
                    || exception instanceof RetryableAgentException) {
                // A retry restarts provider enumeration from page one. Reusing this syncXref after
                // any response may have escaped can assign different contents to an accepted batch
                // index. End this run instead; the listener publishes AGENT_ERROR and the server schedules
                // a later full run with a fresh syncXref.
                throw new PermanentAgentException(errorCode, exception.getMessage(), exception);
            }
            throw exception instanceof RuntimeException runtimeException
                    ? runtimeException
                    : new PermanentAgentException("SYNC_FAILED", "Device sync failed", exception);
        }
    }

    private void appendPage(DeviceIdentitySyncMessage message,
                            List<DeviceIdentityEntry> page,
                            List<DeviceIdentityEntry> buffer,
                            Counters counters) {
        for (DeviceIdentityEntry entry : page) {
            buffer.add(entry);
            if (!fits(message, counters.batchIndex, buffer)) {
                buffer.remove(buffer.size() - 1);
                if (buffer.isEmpty()) {
                    throw new PermanentAgentException(
                            "SYNC_DEVICE_TOO_LARGE", "One device exceeds the configured response byte limit");
                }
                sendBatch(message, counters.batchIndex++, List.copyOf(buffer));
                buffer.clear();
                buffer.add(entry);
                if (!fits(message, counters.batchIndex, buffer)) {
                    throw new PermanentAgentException(
                            "SYNC_DEVICE_TOO_LARGE", "One device exceeds the configured response byte limit");
                }
            }
            counters.total++;
            if (buffer.size() == BATCH_SIZE) {
                sendBatch(message, counters.batchIndex++, List.copyOf(buffer));
                buffer.clear();
            }
        }
    }

    private void sendBatch(DeviceIdentitySyncMessage message,
                           int batchIndex,
                           List<DeviceIdentityEntry> devices) {
        sender.sendDeviceIdentitySyncResponse(response(message, batchIndex, devices));
        // Per batch, so DEBUG: a large tenant pages this hundreds of times per sync, and the server logs
        // the same batch on arrival with what it actually applied. The completion line below is
        // the one that belongs at INFO.
        log.debug("Device-source sync batch sent: source={} sync={} batch={} devices={} correlation={}",
                message.getSourceXref(), message.getSyncXref(), batchIndex, devices.size(),
                message.getCorrelationId());
    }

    private DeviceIdentitySyncResponse response(DeviceIdentitySyncMessage message,
                                                int batchIndex,
                                                List<DeviceIdentityEntry> devices) {
        return DeviceIdentitySyncResponse.builder()
                .requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .sourceXref(message.getSourceXref())
                .syncXref(message.getSyncXref())
                .batchIndex(batchIndex)
                .batchChecksum(checksum(devices))
                .devices(devices)
                .respondedAt(OffsetDateTime.now(clock).toString())
                .build();
    }

    private boolean fits(DeviceIdentitySyncMessage message,
                         int batchIndex,
                         List<DeviceIdentityEntry> devices) {
        try {
            int limit = sourceProperties.getMaxResponseBytes();
            if (limit < DeviceSourceProperties.MIN_RESPONSE_BYTES
                    || limit > DeviceSourceProperties.MAX_RESPONSE_BYTES) {
                throw new PermanentAgentException(
                        "SYNC_CONFIGURATION_INVALID",
                        "max-response-bytes is outside the allowed range");
            }
            return objectMapper.writeValueAsBytes(response(message, batchIndex, devices)).length <= limit;
        } catch (JacksonException exception) {
            throw new PermanentAgentException(
                    "SYNC_SERIALIZATION_FAILED", "Could not size a device response batch", exception);
        }
    }

    private void sendComplete(DeviceIdentitySyncMessage message, int totalDevices, int totalBatches) {
        sender.sendDeviceIdentitySyncComplete(DeviceIdentitySyncCompleteMessage.builder()
                .requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .sourceXref(message.getSourceXref())
                .syncXref(message.getSyncXref())
                .mode("FULL")
                .totalDevices(totalDevices)
                .totalBatches(totalBatches)
                .completedAt(OffsetDateTime.now(clock).toString())
                .build());
        log.info("Device-source sync completed: source={} sync={} devices={} batches={} correlation={}",
                message.getSourceXref(), message.getSyncXref(), totalDevices, totalBatches,
                message.getCorrelationId());
    }

    private String checksum(List<DeviceIdentityEntry> devices) {
        try {
            byte[] payload = objectMapper.writeValueAsString(devices).getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (JacksonException | NoSuchAlgorithmException exception) {
            throw new PermanentAgentException(
                    "SYNC_CHECKSUM_FAILED", "Could not checksum a device batch", exception);
        }
    }

    private static void validate(DeviceIdentitySyncMessage message) {
        if (message.getSourceXref() == null || message.getSourceXref().isBlank()
                || message.getSyncXref() == null || message.getSyncXref().isBlank()
                || message.getConnectionProfileRef() == null || message.getConnectionProfileRef().isBlank()) {
            throw new PermanentAgentException("INVALID_SYNC_COMMAND",
                    "sourceXref, syncXref and connectionProfileRef are required");
        }
        if (!"FULL".equalsIgnoreCase(message.getMode())) {
            throw new PermanentAgentException("INVALID_SYNC_MODE", "Only FULL sync is supported");
        }
    }

    private static final class Counters {
        private int total;
        private int batchIndex;
    }
}
