// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.AgentDeepHealthCheckMessage;
import com.certping.agent.model.message.AgentDeepHealthCheckResponse;
import com.certping.agent.model.message.AgentDeepHealthMetricResult;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AgentDeepHealthCheckProcessor {

    private final AgentProperties properties;
    private final SecretStore secretStore;
    private final AgentMessageSender sender;

    public void process(AgentDeepHealthCheckMessage message, InboundContext context) {
        if (message.getOrganizationId() != null && !message.getOrganizationId().equals(properties.getOrganizationId())) {
            log.warn("Ignoring AGENT_DEEP_HEALTH_CHECK for organizationId={} configuredOrganizationId={}",
                    message.getOrganizationId(), properties.getOrganizationId());
            context.complete();
            return;
        }

        String requestId = message.getRequestId() != null ? message.getRequestId() : ("req-" + UUID.randomUUID());
        String correlationId = message.getCorrelationId() != null ? message.getCorrelationId() : ("corr-" + UUID.randomUUID());
        String deepCheckId = message.getDeepCheckId() != null ? message.getDeepCheckId() : ("dhc-" + UUID.randomUUID());

        List<AgentDeepHealthMetricResult> metrics = new ArrayList<>();
        String status = "SUCCESS";
        String errorCode = null;
        String errorMessage = null;

        try {
            metrics.add(AgentDeepHealthMetricResult.builder()
                    .metricKey("agent.organizationId.present")
                    .metricName("Agent Organization Id Present")
                    .metricGroup("agent_config")
                    .status(properties.getOrganizationId() != null && !properties.getOrganizationId().isBlank() ? "PASS" : "FAIL")
                    .message("Organization id availability check")
                    .build());

            metrics.add(AgentDeepHealthMetricResult.builder()
                    .metricKey("agent.gateway.connection.present")
                    .metricName("Agent Gateway Connection Configured")
                    .metricGroup("agent_config")
                    .status(transportConfigured() ? "PASS" : "FAIL")
                    .message("Agent gateway URL and token availability check")
                    .build());

            List<String> paths = message.getSecretHandles() != null ? message.getSecretHandles() : List.of();
            for (String path : paths) {
                if (path == null || path.isBlank()) {
                    continue;
                }
                String metricKey = "secret_store.path.exists." + Integer.toHexString(path.hashCode());
                try {
                    secretStore.read(path);
                    metrics.add(AgentDeepHealthMetricResult.builder()
                            .metricKey(metricKey)
                            .metricName("Secret Store Path Exists")
                            .metricGroup("secret_store")
                            .status("PASS")
                            .path(path)
                            .message("Secret is readable at provided path")
                            .build());
                } catch (Exception ex) {
                    status = "PARTIAL";
                    metrics.add(AgentDeepHealthMetricResult.builder()
                            .metricKey(metricKey)
                            .metricName("Secret Store Path Exists")
                            .metricGroup("secret_store")
                            .status("FAIL")
                            .path(path)
                            .message("Secret check failed")
                            .details(sanitize(ex.getMessage()))
                            .build());
                }
            }
        } catch (Exception ex) {
            status = "FAILED";
            errorCode = "DEEP_HEALTH_CHECK_FAILED";
            errorMessage = sanitize(ex.getMessage());
        }

        AgentDeepHealthCheckResponse response = AgentDeepHealthCheckResponse.builder()
                .deepCheckId(deepCheckId)
                .requestId(requestId)
                .correlationId(correlationId)
                .organizationId(properties.getOrganizationId())
                .status(status)
                .chunkIndex(message.getChunkIndex() != null ? message.getChunkIndex() : 0)
                .totalChunks(message.getTotalChunks() != null ? message.getTotalChunks() : 1)
                .respondedAt(OffsetDateTime.now(ZoneOffset.UTC).toString())
                .errorCode(errorCode)
                .errorMessage(errorMessage)
                .metrics(metrics)
                .build();

        sender.sendDeepHealthCheckResponse(response);
        context.complete();
        log.info("Processed AGENT_DEEP_HEALTH_CHECK deepCheckId={} chunkIndex={} metricCount={}",
                deepCheckId, response.getChunkIndex(), metrics.size());
    }

    private String sanitize(String raw) {
        if (raw == null) {
            return null;
        }
        String oneLine = raw.replace('\n', ' ').replace('\r', ' ').trim();
        return oneLine.length() > 300 ? oneLine.substring(0, 300) : oneLine;
    }

    private boolean transportConfigured() {
        String url = properties.getTransport().getServerUrl();
        String token = properties.getTransport().getToken();
        return url != null && !url.isBlank() && token != null && !token.isBlank();
    }
}
