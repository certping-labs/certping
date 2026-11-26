// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.CertificateProfileSyncCompleteMessage;
import com.certping.agent.model.message.CertificateCorrelationResult;
import com.certping.agent.model.message.CertificateProfileSyncMessage;
import com.certping.agent.model.message.CertificateProfileSyncResponse;
import com.certping.agent.model.message.ProfileObservedState;
import com.certping.agent.platform.CertificateProfileConnector;
import com.certping.agent.platform.CertificateProfileConnectorFactory;
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

@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateProfileSyncProcessor {
    static final int BATCH_SIZE = 25;

    private final CertificateProfileConnectorFactory connectorFactory;
    private final DeviceSourceProfileRegistry sourceProfileRegistry;
    private final DeviceSourceProperties properties;
    private final AgentMessageSender sender;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public void process(
            CertificateProfileSyncMessage message, InboundContext context) {
        validate(message);
        Counters counters = new Counters();
        List<ProfileObservedState> buffer = new ArrayList<>(BATCH_SIZE);
        try {
            DevicePlatformType provider = DevicePlatformType.fromString(message.getProvider());
            DeviceSourceProfile source = sourceProfileRegistry.require(
                    message.getConnectionProfileRef(), provider);
            CertificateProfileConnector connector = connectorFactory.create(provider);
            connector.streamProfiles(source,
                    page -> appendPage(message, page, buffer, counters));
            flushPendingBatch(message, buffer, counters);
            List<CertificateCorrelationResult> correlations = connector.correlateCertificates(
                    source, message.getCertificateCorrelationCandidates() == null
                            ? List.of() : message.getCertificateCorrelationCandidates());
            sendComplete(message, counters, "SUCCEEDED", null, null, correlations);
            context.complete();
        } catch (Exception exception) {
            if (counters.deliveryUncertain || counters.terminalSent) {
                throw noReplay(exception);
            }
            String code = exception instanceof AgentException agentException
                    ? agentException.getErrorCode() : "PROFILE_SYNC_FAILED";
            log.error("Certificate-profile sync failed: source={} request={} code={}",
                    message.getSourceXref(), message.getRequestId(), code);
            try {
                if (canFlushAfter(exception)) {
                    flushPendingBatch(message, buffer, counters);
                }
                sendComplete(message, counters, "FAILED", code,
                        safeMessage(exception, "Certificate profile sync failed"), null);
                context.complete();
            } catch (Exception deliveryOrSettlementFailure) {
                throw noReplay(deliveryOrSettlementFailure);
            }
        }
    }

    private void appendPage(
            CertificateProfileSyncMessage message,
            List<ProfileObservedState> page,
            List<ProfileObservedState> buffer,
            Counters counters) {
        for (ProfileObservedState profile : page) {
            buffer.add(profile);
            if (!fits(message, counters.batchIndex, buffer)) {
                buffer.removeLast();
                if (buffer.isEmpty()) {
                    throw new PermanentAgentException("PROFILE_SYNC_RECORD_TOO_LARGE",
                            "One profile exceeds the configured response byte limit");
                }
                sendBatch(message, counters.batchIndex, List.copyOf(buffer), counters);
                counters.batchIndex++;
                buffer.clear();
                buffer.add(profile);
                if (!fits(message, counters.batchIndex, buffer)) {
                    buffer.clear();
                    throw new PermanentAgentException("PROFILE_SYNC_RECORD_TOO_LARGE",
                            "One profile exceeds the configured response byte limit");
                }
            }
            counters.total++;
            if (buffer.size() == BATCH_SIZE) {
                sendBatch(message, counters.batchIndex, List.copyOf(buffer), counters);
                counters.batchIndex++;
                buffer.clear();
            }
        }
    }

    private void flushPendingBatch(
            CertificateProfileSyncMessage message,
            List<ProfileObservedState> buffer,
            Counters counters) {
        if (buffer.isEmpty()) {
            return;
        }
        sendBatch(message, counters.batchIndex, List.copyOf(buffer), counters);
        counters.batchIndex++;
        buffer.clear();
    }

    private void sendBatch(
            CertificateProfileSyncMessage message,
            int batchIndex,
            List<ProfileObservedState> profiles,
            Counters counters) {
        try {
            sender.sendCertificateProfileSyncResponse(response(message, batchIndex, profiles));
            // Per batch, so DEBUG — see DeviceIdentitySyncProcessor. The completion line carries
            // the totals worth keeping at INFO.
            log.debug("Certificate-profile sync batch sent: source={} request={} batch={} "
                            + "profiles={} correlation={}",
                    message.getSourceXref(), message.getRequestId(), batchIndex, profiles.size(),
                    message.getCorrelationId());
        } catch (Exception exception) {
            counters.deliveryUncertain = true;
            throw exception;
        }
    }

    private CertificateProfileSyncResponse response(
            CertificateProfileSyncMessage message,
            int batchIndex,
            List<ProfileObservedState> profiles) {
        return CertificateProfileSyncResponse.builder()
                .requestId(message.getRequestId())
                .correlationId(message.getCorrelationId())
                .organizationId(message.getOrganizationId())
                .sourceXref(message.getSourceXref())
                .batchIndex(batchIndex)
                .batchChecksum(checksum(profiles))
                .profiles(profiles)
                .respondedAt(now())
                .build();
    }

    private boolean fits(
            CertificateProfileSyncMessage message,
            int batchIndex,
            List<ProfileObservedState> profiles) {
        int limit = properties.getMaxResponseBytes();
        if (limit < DeviceSourceProperties.MIN_RESPONSE_BYTES
                || limit > DeviceSourceProperties.MAX_RESPONSE_BYTES) {
            throw new PermanentAgentException("SYNC_CONFIGURATION_INVALID",
                    "max-response-bytes is outside the allowed range");
        }
        try {
            return objectMapper.writeValueAsBytes(response(message, batchIndex, profiles)).length <= limit;
        } catch (JacksonException exception) {
            throw new PermanentAgentException("PROFILE_SYNC_SERIALIZATION_FAILED",
                    "Could not size a profile response batch", exception);
        }
    }

    private void sendComplete(
            CertificateProfileSyncMessage message,
            Counters counters,
            String status,
            String errorCode,
            String errorMessage,
            List<CertificateCorrelationResult> correlations) {
        try {
            sender.sendCertificateProfileSyncComplete(CertificateProfileSyncCompleteMessage.builder()
                    .requestId(message.getRequestId())
                    .correlationId(message.getCorrelationId())
                    .organizationId(message.getOrganizationId())
                    .sourceXref(message.getSourceXref())
                    .totalProfiles(counters.total)
                    .totalBatches(counters.batchIndex)
                    .status(status)
                    .errorCode(errorCode)
                    .errorMessage(errorMessage)
                    .certificateCorrelations(correlations)
                    .completedAt(now())
                    .build());
            counters.terminalSent = true;
            log.info("Certificate-profile sync completed: source={} request={} status={} profiles={} "
                            + "batches={} correlations={} correlation={}",
                    message.getSourceXref(), message.getRequestId(), status, counters.total,
                    counters.batchIndex, correlations == null ? 0 : correlations.size(),
                    message.getCorrelationId());
        } catch (Exception exception) {
            counters.deliveryUncertain = true;
            throw exception;
        }
    }

    private String checksum(List<ProfileObservedState> profiles) {
        try {
            byte[] payload = objectMapper.writeValueAsString(profiles)
                    .getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (JacksonException | NoSuchAlgorithmException exception) {
            throw new PermanentAgentException("PROFILE_SYNC_CHECKSUM_FAILED",
                    "Could not checksum a profile batch", exception);
        }
    }

    private String now() {
        return OffsetDateTime.now(clock).toString();
    }

    private static void validate(CertificateProfileSyncMessage message) {
        if (blank(message.getRequestId()) || blank(message.getOrganizationId())
                || blank(message.getSourceXref())
                || blank(message.getConnectionProfileRef()) || blank(message.getProvider())) {
            throw new PermanentAgentException("INVALID_PROFILE_SYNC_COMMAND",
                    "requestId, organizationId, sourceXref, connectionProfileRef and provider are required");
        }
    }

    private static String safeMessage(Exception exception, String fallback) {
        String value = exception instanceof AgentException ? exception.getMessage() : fallback;
        if (value == null || value.isBlank()) value = fallback;
        return value.length() <= 1000 ? value : value.substring(0, 1000);
    }

    private static boolean canFlushAfter(Exception exception) {
        if (!(exception instanceof AgentException agentException)) {
            return true;
        }
        return !List.of(
                "PROFILE_SYNC_RECORD_TOO_LARGE",
                "PROFILE_SYNC_SERIALIZATION_FAILED",
                "SYNC_CONFIGURATION_INVALID",
                "PROFILE_SYNC_CHECKSUM_FAILED")
                .contains(agentException.getErrorCode());
    }

    private static PermanentAgentException noReplay(Exception exception) {
        String code = exception instanceof AgentException agentException
                ? agentException.getErrorCode() : "PROFILE_SYNC_RESPONSE_DELIVERY_FAILED";
        return new PermanentAgentException(code,
                safeMessage(exception,
                        "Profile sync response delivery is uncertain; start a fresh request"),
                exception);
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static final class Counters {
        private int total;
        private int batchIndex;
        private boolean deliveryUncertain;
        private boolean terminalSent;
    }
}
