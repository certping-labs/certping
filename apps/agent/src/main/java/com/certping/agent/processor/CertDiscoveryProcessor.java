// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.discovery.DiscoveryAdapter;
import com.certping.agent.discovery.DiscoveryAdapterFactory;
import com.certping.agent.discovery.DiscoveryResult;
import com.certping.agent.model.message.DiscoveryFailedScope;
import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryCompleteMessage;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.CertDiscoveryResponse;
import com.certping.agent.model.message.DiscoveredCertEntry;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles {@code CERT_DISCOVERY} commands from this organization's inbound queue.
 *
 * <p>Delegates scanning to the appropriate {@link DiscoveryAdapter}, then publishes one or more
 * {@code CERT_DISCOVERY_RESPONSE} messages before completing the inbound message. Large result
 * sets are split into batches of {@value #BATCH_SIZE}; Kubernetes discovery starts at
 * {@value #KUBERNETES_BATCH_SIZE} because its usage graph is larger. Kubernetes batches are
 * serialized before any response is sent and split further when needed to stay within the
 * message payload budget. Each batch carries {@code batchIndex} (0-based) and
 * {@code totalBatches} so the server can track when all batches have arrived.
 */
@Slf4j
@Component
public class CertDiscoveryProcessor {

    static final int BATCH_SIZE = 50;
    static final int KUBERNETES_BATCH_SIZE = 10;
    static final int MAX_MESSAGE_BYTES = 240 * 1024;

    private final DiscoveryAdapterFactory adapterFactory;
    private final AgentMessageSender sender;
    private final ObjectMapper objectMapper;

    @Autowired
    public CertDiscoveryProcessor(DiscoveryAdapterFactory adapterFactory,
            AgentMessageSender sender,
            ObjectMapper objectMapper) {
        this.adapterFactory = adapterFactory;
        this.sender = sender;
        this.objectMapper = objectMapper;
    }

    // Kept for focused unit tests that do not need payload-size preflight.
    CertDiscoveryProcessor(DiscoveryAdapterFactory adapterFactory, AgentMessageSender sender) {
        this(adapterFactory, sender, JsonMapper.builderWithJackson2Defaults().build());
    }

    public void process(CertDiscoveryMessage message, InboundContext context) {
        log.info("Processing CERT_DISCOVERY — targetType={}, organizationId={}, requestedAt={}",
                message.getTargetType(), message.getOrganizationId(), message.getRequestedAt());

        try {
            DiscoveryAdapter adapter = adapterFactory.create(message.getTargetType());
            DiscoveryResult result = adapter.discoverWithFailedScopes(message);
            List<DiscoveredCertEntry> discovered = result.certificates();
            List<DiscoveryFailedScope> failedScopes = result.failedScopes();
            if (result.partial()) {
                log.warn("CERT_DISCOVERY partial: organizationId={}, targetType={}, failedScopes={}",
                        message.getOrganizationId(), message.getTargetType(), failedScopes.size());
            }

            String respondedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();
            List<CertDiscoveryResponse> responses = buildResponses(message, discovered, failedScopes, respondedAt);
            int totalBatches = responses.size();

            for (int i = 0; i < totalBatches; i++) {
                CertDiscoveryResponse response = responses.get(i);
                sender.sendDiscoveryResponse(response);
                log.info("Sent CERT_DISCOVERY_RESPONSE batch {}/{}: organizationId={}, targetType={}, batchSize={}",
                        i + 1, totalBatches, message.getOrganizationId(), message.getTargetType(), response.getDiscoveredCerts().size());
            }

            sender.sendDiscoveryComplete(
                    CertDiscoveryCompleteMessage.builder()
                            .requestId(message.getRequestId())
                            .organizationId(message.getOrganizationId())
                            .targetType(message.getTargetType())
                            .totalCerts(discovered.size())
                            .completedAt(OffsetDateTime.now(ZoneOffset.UTC).toString())
                            .failedScopes(failedScopes)
                            .build());

            context.complete();
            log.info("CERT_DISCOVERY complete: organizationId={}, targetType={}, totalCerts={}, batches={}",
                    message.getOrganizationId(), message.getTargetType(), discovered.size(), totalBatches);

        } catch (Exception e) {
            if (message.getTargetType() == TargetType.KUBERNETES_SECRETS) {
                log.error("CERT_DISCOVERY failed: organizationId={}, targetType={}, exceptionType={}, errorCode={}",
                        message.getOrganizationId(), message.getTargetType(), e.getClass().getSimpleName(),
                        e instanceof AgentException agentException
                                ? agentException.getErrorCode()
                                : "DISCOVERY_FAILED");
            } else {
                log.error("CERT_DISCOVERY failed: organizationId={}, targetType={}, error={}",
                        message.getOrganizationId(), message.getTargetType(), e.getMessage(), e);
            }
            throw e instanceof RuntimeException re ? re
                    : new PermanentAgentException("DISCOVERY_FAILED", e.getMessage(), e);
        }
    }

    private static <T> List<List<T>> partition(List<T> list, int size) {
        if (list.isEmpty()) {
            return List.of(List.of());
        }
        int total = list.size();
        int numBatches = (total + size - 1) / size;
        List<List<T>> result = new java.util.ArrayList<>(numBatches);
        for (int i = 0; i < total; i += size) {
            result.add(list.subList(i, Math.min(i + size, total)));
        }
        return result;
    }

    private List<CertDiscoveryResponse> buildResponses(CertDiscoveryMessage message,
            List<DiscoveredCertEntry> discovered,
            List<DiscoveryFailedScope> failedScopes,
            String respondedAt) {
        int batchSize = batchSizeFor(message);
        if (message.getTargetType() == com.certping.agent.model.enums.TargetType.KUBERNETES_SECRETS) {
            return preflightKubernetesResponseSizes(message, discovered, failedScopes, respondedAt, batchSize);
        }
        return toResponses(message, partition(discovered, batchSize), failedScopes, respondedAt);
    }

    private int batchSizeFor(CertDiscoveryMessage message) {
        return message.getTargetType() == com.certping.agent.model.enums.TargetType.KUBERNETES_SECRETS
                ? KUBERNETES_BATCH_SIZE
                : BATCH_SIZE;
    }

    private List<CertDiscoveryResponse> preflightKubernetesResponseSizes(CertDiscoveryMessage message,
            List<DiscoveredCertEntry> discovered,
            List<DiscoveryFailedScope> failedScopes,
            String respondedAt,
            int initialBatchSize) {
        int batchSize = initialBatchSize;
        while (batchSize >= 1) {
            List<CertDiscoveryResponse> responses = toResponses(message, partition(discovered, batchSize),
                    failedScopes, respondedAt);
            OversizedResponse oversized = firstOversizedResponse(responses);
            if (oversized == null) {
                return responses;
            }
            if (batchSize == 1) {
                String resourceId = oversized.response().getDiscoveredCerts().isEmpty()
                        ? "<empty>"
                        : oversized.response().getDiscoveredCerts().get(0).getResourceId();
                throw new PermanentAgentException("DISCOVERY_K8S_RESPONSE_TOO_LARGE",
                        "Kubernetes discovery response for resourceId=" + resourceId
                                + " exceeds message payload budget after one-cert batching"
                                + " serializedBytes=" + oversized.bytes());
            }
            batchSize = Math.max(1, batchSize / 2);
        }
        throw new PermanentAgentException("DISCOVERY_K8S_RESPONSE_TOO_LARGE",
                "Kubernetes discovery response exceeds message payload budget");
    }

    private List<CertDiscoveryResponse> toResponses(CertDiscoveryMessage message,
            List<List<DiscoveredCertEntry>> batches,
            List<DiscoveryFailedScope> failedScopes,
            String respondedAt) {
        List<CertDiscoveryResponse> responses = new ArrayList<>(batches.size());
        int totalBatches = batches.size();
        for (int i = 0; i < totalBatches; i++) {
            responses.add(CertDiscoveryResponse.builder()
                    .requestId(message.getRequestId())
                    .correlationId(message.getCorrelationId())
                    .organizationId(message.getOrganizationId())
                    .targetType(message.getTargetType())
                    .status("SUCCESS")
                    .discoveredCerts(batches.get(i))
                    .respondedAt(respondedAt)
                    .batchIndex(i)
                    .totalBatches(totalBatches)
                    .failedScopes(failedScopes)
                    .build());
        }
        return responses;
    }

    private OversizedResponse firstOversizedResponse(List<CertDiscoveryResponse> responses) {
        for (CertDiscoveryResponse response : responses) {
            int bytes = serializedSizeBytes(response);
            if (bytes > MAX_MESSAGE_BYTES) {
                return new OversizedResponse(response, bytes);
            }
        }
        return null;
    }

    private int serializedSizeBytes(CertDiscoveryResponse response) {
        try {
            return objectMapper.writeValueAsString(response).getBytes(StandardCharsets.UTF_8).length;
        } catch (JacksonException e) {
            throw new PermanentAgentException("SERIALIZATION_FAILED",
                    "Failed to serialize CERT_DISCOVERY_RESPONSE: " + e.getMessage(), e);
        }
    }

    private record OversizedResponse(CertDiscoveryResponse response, int bytes) {
    }
}
