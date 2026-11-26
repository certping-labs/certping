// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.CertificateProfileSyncCompleteMessage;
import com.certping.agent.model.message.CertificateProfileSyncMessage;
import com.certping.agent.model.message.CertificateProfileSyncResponse;
import com.certping.agent.model.message.ProfileObservedState;
import com.certping.agent.platform.CertificateProfileConnector;
import com.certping.agent.platform.CertificateProfileConnectorFactory;
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
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateProfileSyncProcessorTest {
    private static final DeviceSourceProfile SOURCE = new DeviceSourceProfile(
            "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
            "Primary", null, Map.of());

    @Mock private CertificateProfileConnectorFactory connectorFactory;
    @Mock private DeviceSourceProfileRegistry sourceRegistry;
    @Mock private CertificateProfileConnector connector;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;
    private CertificateProfileSyncProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new CertificateProfileSyncProcessor(
                connectorFactory, sourceRegistry, new DeviceSourceProperties(), sender,
                JsonMapper.builderWithJackson2Defaults().build(),
                Clock.fixed(Instant.parse("2026-08-25T00:00:00Z"), ZoneOffset.UTC));
        when(sourceRegistry.require("intune-primary", DevicePlatformType.INTUNE))
                .thenReturn(SOURCE);
        when(connectorFactory.create(DevicePlatformType.INTUNE)).thenReturn(connector);
    }

    @Test
    void flushesValidBufferedProfilesBeforeFailedCompletion() {
        ProfileObservedState valid = ProfileObservedState.builder()
                .providerProfileId("native-1").build();
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Consumer<List<ProfileObservedState>> consumer = invocation.getArgument(1);
            consumer.accept(List.of(valid));
            throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID", "Malformed sibling");
        }).when(connector).streamProfiles(any(), any());

        processor.process(message(), context);

        ArgumentCaptor<CertificateProfileSyncResponse> part =
                ArgumentCaptor.forClass(CertificateProfileSyncResponse.class);
        verify(sender).sendCertificateProfileSyncResponse(part.capture());
        assertThat(part.getValue().getProfiles()).containsExactly(valid);
        assertThat(part.getValue().getBatchIndex()).isZero();
        ArgumentCaptor<CertificateProfileSyncCompleteMessage> completion =
                ArgumentCaptor.forClass(CertificateProfileSyncCompleteMessage.class);
        verify(sender).sendCertificateProfileSyncComplete(completion.capture());
        assertThat(completion.getValue().getStatus()).isEqualTo("FAILED");
        assertThat(completion.getValue().getTotalProfiles()).isEqualTo(1);
        assertThat(completion.getValue().getTotalBatches()).isEqualTo(1);
        verify(context).complete();
    }

    @Test
    void convertsUncertainPartPublicationIntoPermanentNoReplayFailure() {
        ProfileObservedState valid = ProfileObservedState.builder()
                .providerProfileId("native-1").build();
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Consumer<List<ProfileObservedState>> consumer = invocation.getArgument(1);
            consumer.accept(List.of(valid));
            return null;
        }).when(connector).streamProfiles(any(), any());
        doThrow(new TransientAgentException("SEND_FAILED", "gateway acknowledgement lost"))
                .when(sender).sendCertificateProfileSyncResponse(any());

        assertThatThrownBy(() -> processor.process(message(), context))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode()).isEqualTo("SEND_FAILED"));
        verify(sender, never()).sendCertificateProfileSyncComplete(any());
        verify(context, never()).complete();
    }

    private static CertificateProfileSyncMessage message() {
        return CertificateProfileSyncMessage.builder()
                .requestId("profile-sync-1")
                .correlationId("profile-sync-1")
                .organizationId("1")
                .sourceXref("source-1")
                .connectionProfileRef("intune-primary")
                .provider("INTUNE")
                .build();
    }
}
