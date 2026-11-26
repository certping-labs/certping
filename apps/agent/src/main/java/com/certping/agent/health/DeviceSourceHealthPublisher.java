// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.AgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.DeviceSourceHealthMessage;
import com.certping.agent.platform.DeviceIdentityConnector;
import com.certping.agent.platform.DeviceIdentityConnectorFactory;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/** Agent-owned provider health schedule. The server receives observations but never triggers them. */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeviceSourceHealthPublisher {
    private final AgentProperties agentProperties;
    private final DeviceSourceProfileRegistry profileRegistry;
    private final DeviceIdentityConnectorFactory connectorFactory;
    private final AgentMessageSender sender;
    private final Clock clock;

    private final String agentInstanceXref = xref("agentinst_");
    private final AtomicLong sequence = new AtomicLong();

    @Scheduled(
            initialDelayString = "${agent.device-sources.health-initial-delay:15s}",
            fixedDelayString = "${agent.device-sources.health-interval:5m}")
    public void publishHealth() {
        for (DeviceSourceProfile profile : profileRegistry.all()) {
            try {
                publish(profile);
            } catch (Exception exception) {
                log.error("Could not publish device-source health: profile={} provider={} code={}",
                        profile.profileRef(), profile.provider(), errorCode(exception), exception);
            }
        }
    }

    private void publish(DeviceSourceProfile profile) {
        OffsetDateTime startedAt = OffsetDateTime.now(clock);
        long startedNanos = System.nanoTime();
        String healthStatus = "HEALTHY";
        String providerStatus = "CONNECTED";
        String statusMessage = null;
        Map<String, Object> healthMetadata;
        try {
            DeviceIdentityConnector.ConnectionTestResult result = connectorFactory
                    .create(profile.provider()).testConnectionDetails(profile);
            healthStatus = result.healthStatus();
            providerStatus = result.providerStatus();
            statusMessage = result.statusMessage();
            LinkedHashMap<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("visibleDeviceSample", result.visibleDeviceSample());
            metadata.putAll(result.metadata());
            healthMetadata = Map.copyOf(metadata);
        } catch (Exception exception) {
            healthStatus = "UNHEALTHY";
            providerStatus = exception instanceof AgentException agentException
                    ? agentException.getErrorCode() : "HEALTH_CHECK_FAILED";
            statusMessage = "Provider health check failed";
            healthMetadata = Map.of("permissionsValidated", false);
            log.warn("Device-source health failed: profile={} provider={} code={}",
                    profile.profileRef(), profile.provider(), providerStatus);
        }

        OffsetDateTime observedAt = OffsetDateTime.now(clock);
        sender.sendDeviceSourceHealth(DeviceSourceHealthMessage.builder()
                .healthXref(xref("health_"))
                .correlationId(xref("corr_"))
                .organizationId(agentProperties.getOrganizationId())
                .connectionProfileRef(profile.profileRef())
                .provider(profile.provider().name())
                .sourceCategory(profile.sourceCategory())
                .displayName(profile.displayName())
                .description(profile.description())
                .configurationMetadata(profile.metadata())
                .healthStatus(healthStatus)
                .providerStatus(providerStatus)
                .statusMessage(statusMessage)
                .healthMetadata(healthMetadata)
                .agentInstanceXref(agentInstanceXref)
                .agentSequence(sequence.incrementAndGet())
                .checkStartedAt(startedAt.toString())
                .observedAt(observedAt.toString())
                .publishedAt(OffsetDateTime.now(clock).toString())
                .responseTimeMs((System.nanoTime() - startedNanos) / 1_000_000L)
                .build());
    }

    private static String xref(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }

    private static String errorCode(Exception exception) {
        return exception instanceof AgentException agentException
                ? agentException.getErrorCode() : "HEALTH_PUBLISH_FAILED";
    }
}
