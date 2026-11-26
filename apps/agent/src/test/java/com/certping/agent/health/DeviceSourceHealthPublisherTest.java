// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.DeviceSourceHealthMessage;
import com.certping.agent.platform.DeviceIdentityConnector;
import com.certping.agent.platform.DeviceIdentityConnectorFactory;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceSourceHealthPublisherTest {
    @Mock private DeviceSourceProfileRegistry profileRegistry;
    @Mock private DeviceIdentityConnectorFactory connectorFactory;
    @Mock private DeviceIdentityConnector connector;
    @Mock private AgentMessageSender sender;

    @Test
    void publishesAgentOwnedHealthWithMonotonicSequenceAndSourceMetadata() {
        AgentProperties agentProperties = new AgentProperties();
        agentProperties.setOrganizationId("42");
        DeviceSourceProfile profile = new DeviceSourceProfile(
                "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
                "Primary Intune", "Production devices",
                Map.of("environment", "production"));
        when(profileRegistry.all()).thenReturn(List.of(profile));
        when(connectorFactory.create(DevicePlatformType.INTUNE)).thenReturn(connector);
        when(connector.testConnectionDetails(profile)).thenReturn(
                new DeviceIdentityConnector.ConnectionTestResult(1, Map.of(
                        "managedDevicesReadValidated", true,
                        "entraDevicesReadValidated", true)));
        Clock clock = Clock.fixed(Instant.parse("2026-08-24T10:00:00Z"), ZoneOffset.UTC);
        DeviceSourceHealthPublisher publisher = new DeviceSourceHealthPublisher(
                agentProperties, profileRegistry, connectorFactory, sender, clock);

        publisher.publishHealth();
        publisher.publishHealth();

        ArgumentCaptor<DeviceSourceHealthMessage> messages =
                ArgumentCaptor.forClass(DeviceSourceHealthMessage.class);
        verify(sender, times(2)).sendDeviceSourceHealth(messages.capture());
        DeviceSourceHealthMessage first = messages.getAllValues().get(0);
        DeviceSourceHealthMessage second = messages.getAllValues().get(1);
        assertThat(first.getOrganizationId()).isEqualTo("42");
        assertThat(first.getConnectionProfileRef()).isEqualTo("intune-primary");
        assertThat(first.getConfigurationMetadata()).containsEntry("environment", "production");
        assertThat(first.getHealthStatus()).isEqualTo("HEALTHY");
        assertThat(first.getHealthMetadata()).containsEntry("managedDevicesReadValidated", true)
                .containsEntry("entraDevicesReadValidated", true);
        assertThat(first.getAgentSequence()).isEqualTo(1L);
        assertThat(second.getAgentSequence()).isEqualTo(2L);
        assertThat(second.getAgentInstanceXref()).isEqualTo(first.getAgentInstanceXref());
        assertThat(first.getObservedAt()).isEqualTo("2026-08-24T10:00Z");
        assertThat(first.getResponseTimeMs()).isNotNegative();
    }

    @Test
    void onePublicationFailureDoesNotSkipLaterProfiles() {
        AgentProperties agentProperties = new AgentProperties();
        agentProperties.setOrganizationId("42");
        DeviceSourceProfile first = new DeviceSourceProfile(
                "first", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
                "First", null, Map.of());
        DeviceSourceProfile second = new DeviceSourceProfile(
                "second", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
                "Second", null, Map.of());
        when(profileRegistry.all()).thenReturn(List.of(first, second));
        when(connectorFactory.create(DevicePlatformType.INTUNE)).thenReturn(connector);
        when(connector.testConnectionDetails(first)).thenReturn(
                new DeviceIdentityConnector.ConnectionTestResult(1, Map.of()));
        when(connector.testConnectionDetails(second)).thenReturn(
                new DeviceIdentityConnector.ConnectionTestResult(1, Map.of()));
        doThrow(new IllegalStateException("server unavailable"))
                .doNothing().when(sender).sendDeviceSourceHealth(any());
        DeviceSourceHealthPublisher publisher = new DeviceSourceHealthPublisher(
                agentProperties, profileRegistry, connectorFactory, sender, Clock.systemUTC());

        publisher.publishHealth();

        verify(sender, times(2)).sendDeviceSourceHealth(any());
    }
}
