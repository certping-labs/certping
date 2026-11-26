// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
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
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceIdentitySyncProcessorTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-08-24T10:00:00Z"), ZoneOffset.UTC);
    private static final DeviceSourceProfile PROFILE = new DeviceSourceProfile(
            "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
            "Primary Intune", null, Map.of());

    @Mock private DeviceIdentityConnectorFactory connectorFactory;
    @Mock private DeviceSourceProfileRegistry profileRegistry;
    @Mock private DeviceIdentityConnector connector;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;
    private DeviceIdentitySyncProcessor processor;
    private DeviceSourceProperties sourceProperties;

    @BeforeEach
    void setUp() {
        sourceProperties = new DeviceSourceProperties();
        processor = new DeviceIdentitySyncProcessor(
                connectorFactory, profileRegistry, sourceProperties, sender, JsonMapper.builderWithJackson2Defaults().build(), CLOCK);
    }

    private static DeviceIdentitySyncMessage message() {
        DeviceIdentitySyncMessage message = new DeviceIdentitySyncMessage();
        message.setRequestId("request-1");
        message.setCorrelationId("correlation-1");
        message.setOrganizationId("1");
        message.setSourceXref("source-1");
        message.setProvider("INTUNE");
        message.setConnectionProfileRef("intune-primary");
        message.setSyncXref("sync-1");
        message.setMode("FULL");
        return message;
    }

    private static List<DeviceIdentityEntry> devices(int count) {
        return IntStream.range(0, count)
                .mapToObj(index -> DeviceIdentityEntry.builder().externalId("device-" + index).build())
                .toList();
    }

    private void connectorReturns(List<DeviceIdentityEntry> page) {
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Consumer<List<DeviceIdentityEntry>> consumer = invocation.getArgument(1);
            consumer.accept(page);
            return null;
        }).when(connector).streamDevices(any(), any());
    }

    private void configureConnector() {
        when(profileRegistry.require("intune-primary", DevicePlatformType.INTUNE)).thenReturn(PROFILE);
        when(connectorFactory.create(DevicePlatformType.INTUNE)).thenReturn(connector);
    }

    @Test
    void resolvesOnlyTheNamedLocalProfile() {
        configureConnector();
        connectorReturns(devices(1));

        processor.process(message(), context);

        verify(profileRegistry).require("intune-primary", DevicePlatformType.INTUNE);
        verify(connector).streamDevices(any(DeviceSourceProfile.class), any());
        verify(context).complete();
    }

    @Test
    void splitsFleetIntoIndexedChecksummedBatches() {
        configureConnector();
        connectorReturns(devices(120));

        processor.process(message(), context);

        ArgumentCaptor<DeviceIdentitySyncResponse> batches =
                ArgumentCaptor.forClass(DeviceIdentitySyncResponse.class);
        verify(sender, times(3)).sendDeviceIdentitySyncResponse(batches.capture());
        assertThat(batches.getAllValues()).extracting(DeviceIdentitySyncResponse::getBatchIndex)
                .containsExactly(0, 1, 2);
        assertThat(batches.getAllValues()).extracting(batch -> batch.getDevices().size())
                .containsExactly(50, 50, 20);
        assertThat(batches.getAllValues()).allSatisfy(batch -> {
            assertThat(batch.getSourceXref()).isEqualTo("source-1");
            assertThat(batch.getSyncXref()).isEqualTo("sync-1");
            assertThat(batch.getBatchChecksum()).hasSize(64);
            assertThat(batch.getRespondedAt()).isEqualTo("2026-08-24T10:00Z");
        });
    }

    @Test
    void sendsCompletionAfterAllBatches() {
        configureConnector();
        connectorReturns(devices(3));

        processor.process(message(), context);

        ArgumentCaptor<DeviceIdentitySyncCompleteMessage> completion =
                ArgumentCaptor.forClass(DeviceIdentitySyncCompleteMessage.class);
        verify(sender).sendDeviceIdentitySyncComplete(completion.capture());
        assertThat(completion.getValue().getSourceXref()).isEqualTo("source-1");
        assertThat(completion.getValue().getSyncXref()).isEqualTo("sync-1");
        assertThat(completion.getValue().getTotalDevices()).isEqualTo(3);
        assertThat(completion.getValue().getTotalBatches()).isEqualTo(1);
        assertThat(completion.getValue().getCompletedAt()).isEqualTo("2026-08-24T10:00Z");
    }

    @Test
    void rejectsModesOtherThanFull() {
        DeviceIdentitySyncMessage message = message();
        message.setMode("TEST");

        assertThatThrownBy(() -> processor.process(message, context))
                .isInstanceOf(PermanentAgentException.class);

        verify(connectorFactory, never()).create(any());
        verify(sender, never()).sendDeviceIdentitySyncComplete(any());
    }

    @Test
    void transientFailureAfterPublishedBatchTerminatesTheRun() {
        configureConnector();
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Consumer<List<DeviceIdentityEntry>> consumer = invocation.getArgument(1);
            consumer.accept(devices(50));
            throw new TransientAgentException("PLATFORM_THROTTLED", "Graph throttled");
        }).when(connector).streamDevices(any(), any());

        assertThatThrownBy(() -> processor.process(message(), context))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "PLATFORM_THROTTLED")
                .hasMessage("Graph throttled");

        verify(sender).sendDeviceIdentitySyncResponse(any());
        verify(sender, never()).sendDeviceIdentitySyncComplete(any());
        verify(context, never()).complete();
    }

    @Test
    void throttlingBeforeFirstBatchAlsoTerminatesTheRun() {
        configureConnector();
        doAnswer(invocation -> {
            throw new RetryableAgentException(
                    "PLATFORM_THROTTLED", "Graph throttled", Duration.ofMinutes(5));
        }).when(connector).streamDevices(any(), any());

        assertThatThrownBy(() -> processor.process(message(), context))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "PLATFORM_THROTTLED")
                .hasMessage("Graph throttled");

        verify(sender, never()).sendDeviceIdentitySyncResponse(any());
        verify(sender, never()).sendDeviceIdentitySyncComplete(any());
        verify(context, never()).complete();
    }

    @Test
    void splitsBySerializedUtf8BytesBeforeTheResponseLimit() {
        sourceProperties.setMaxResponseBytes(1_200);
        configureConnector();
        connectorReturns(List.of(
                DeviceIdentityEntry.builder().externalId("device-1").deviceName("é".repeat(350)).build(),
                DeviceIdentityEntry.builder().externalId("device-2").deviceName("é".repeat(350)).build()));

        processor.process(message(), context);

        ArgumentCaptor<DeviceIdentitySyncResponse> batches =
                ArgumentCaptor.forClass(DeviceIdentitySyncResponse.class);
        verify(sender, times(2)).sendDeviceIdentitySyncResponse(batches.capture());
        assertThat(batches.getAllValues()).allSatisfy(batch ->
                assertThat(batch.getDevices()).hasSize(1));
    }

    @Test
    void rejectsOneDeviceThatCannotFitInAResponse() {
        sourceProperties.setMaxResponseBytes(1_024);
        configureConnector();
        connectorReturns(List.of(DeviceIdentityEntry.builder()
                .externalId("device-1").deviceName("x".repeat(5_000)).build()));

        assertThatThrownBy(() -> processor.process(message(), context))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("exceeds the configured response byte limit");

        verify(sender, never()).sendDeviceIdentitySyncResponse(any());
        verify(sender, never()).sendDeviceIdentitySyncComplete(any());
    }
}
