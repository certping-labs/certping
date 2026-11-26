// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.PermanentAgentException;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateProfileProcessorTest {
    private static final DeviceSourceProfile SOURCE = new DeviceSourceProfile(
            "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
            "Primary", null, Map.of());

    @Mock private CertificateProfileConnectorFactory connectorFactory;
    @Mock private DeviceSourceProfileRegistry sourceRegistry;
    @Mock private CertificateProfileConnector connector;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;
    private CertificateProfileProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new CertificateProfileProcessor(
                connectorFactory, sourceRegistry, sender,
                Clock.fixed(Instant.parse("2026-08-25T00:00:00Z"), ZoneOffset.UTC));
        when(sourceRegistry.require("intune-primary", DevicePlatformType.INTUNE))
                .thenReturn(SOURCE);
        when(connectorFactory.create(DevicePlatformType.INTUNE)).thenReturn(connector);
    }

    @Test
    void letsTransientMutationFailureReachTheListenerForScheduledRetry() {
        CertificateProfileMessage message = message();
        when(connector.create(SOURCE, message)).thenThrow(
                new TransientAgentException("PLATFORM_REQUEST_UNAVAILABLE", "Graph unavailable"));

        assertThatThrownBy(() -> processor.process(message, context))
                .isInstanceOf(TransientAgentException.class)
                .hasMessageContaining("Graph unavailable");
        verify(sender, never()).sendCertificateProfileResponse(
                org.mockito.ArgumentMatchers.any());
        verify(context, never()).complete();
    }

    @Test
    void neverSendsFailedAfterSuccessfulMutationWhenSerializationFails() {
        CertificateProfileMessage message = message();
        ProfileObservedState observed = ProfileObservedState.builder()
                .providerProfileId("native-1").build();
        when(connector.create(SOURCE, message)).thenReturn(observed);
        doThrow(new PermanentAgentException("SERIALIZATION_FAILED", "Could not serialize"))
                .when(sender).sendCertificateProfileResponse(any());

        assertThatThrownBy(() -> processor.process(message, context))
                .isInstanceOfSatisfying(PermanentAgentException.class, error -> {
                    assertThat(error.getErrorCode()).isEqualTo("PROFILE_RESPONSE_DELIVERY_FAILED");
                    assertThat(error).hasMessageContaining("mutation succeeded");
                });
        ArgumentCaptor<CertificateProfileResponse> response =
                ArgumentCaptor.forClass(CertificateProfileResponse.class);
        verify(sender, times(1)).sendCertificateProfileResponse(response.capture());
        assertThat(response.getValue().getStatus()).isEqualTo("SUCCEEDED");
        verify(context, never()).complete();
    }

    @Test
    void preventsReplayWhenSuccessfulMutationResponseDeliveryIsTransient() {
        CertificateProfileMessage message = message();
        when(connector.create(SOURCE, message)).thenReturn(ProfileObservedState.builder()
                .providerProfileId("native-1").build());
        doThrow(new TransientAgentException("SEND_FAILED", "gateway acknowledgement lost"))
                .when(sender).sendCertificateProfileResponse(any());

        assertThatThrownBy(() -> processor.process(message, context))
                .isInstanceOfSatisfying(PermanentAgentException.class, error -> {
                    assertThat(error.getErrorCode()).isEqualTo("PROFILE_RESPONSE_DELIVERY_FAILED");
                    assertThat(error.getCause()).isInstanceOfSatisfying(
                            TransientAgentException.class,
                            cause -> assertThat(cause.getErrorCode()).isEqualTo("SEND_FAILED"));
                });
        verify(sender, times(1)).sendCertificateProfileResponse(any());
        verify(context, never()).complete();
    }

    private static CertificateProfileMessage message() {
        return CertificateProfileMessage.builder()
                .requestId("request-1")
                .organizationId("1")
                .sourceXref("source-1")
                .connectionProfileRef("intune-primary")
                .provider("INTUNE")
                .profileXref("profile-1")
                .operationXref("operation-1")
                .operation("CREATE")
                .desiredRevision(1L)
                .build();
    }
}
