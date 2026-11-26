// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.PermanentAgentException;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceSyncProcessorTest {

    @Mock private DeviceSourceProfileRegistry profileRegistry;
    @Mock private IntuneSessionProvider sessionProvider;
    @Mock private IntuneGraphClient graphClient;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;
    @Mock private DeviceSourceProfile profile;

    private final Clock clock = Clock.fixed(Instant.parse("2026-08-28T00:00:00Z"), ZoneOffset.UTC);

    private IotDeviceSyncProcessor processor() {
        return new IotDeviceSyncProcessor(profileRegistry, sessionProvider, graphClient, sender, clock);
    }

    private static IotDeviceSyncMessage message(String provider) {
        IotDeviceSyncMessage m = new IotDeviceSyncMessage();
        m.setRequestId("r");
        m.setCorrelationId("c");
        m.setOrganizationId("42");
        m.setSourceXref("src");
        m.setProvider(provider);
        m.setConnectionProfileRef("intune-primary");
        m.setManagedDeviceId("11111111-1111-1111-1111-111111111111");
        m.setDeviceXref("dev-1");
        m.setCertificateXrefs(java.util.List.of("crt-1"));
        return m;
    }

    private IotDeviceSyncResponse capture() {
        ArgumentCaptor<IotDeviceSyncResponse> captor = ArgumentCaptor.forClass(IotDeviceSyncResponse.class);
        verify(sender).sendIotDeviceSyncResponse(captor.capture());
        verify(context).complete();
        return captor.getValue();
    }

    @Test
    void nudgeSentOnSuccessfulSync() {
        when(profileRegistry.require("intune-primary", DevicePlatformType.INTUNE)).thenReturn(profile);
        when(sessionProvider.open(profile)).thenReturn(new IntuneSession("token"));

        processor().process(message("INTUNE"), context);

        verify(graphClient).syncDevice("token", "11111111-1111-1111-1111-111111111111");
        IotDeviceSyncResponse response = capture();
        assertThat(response.getOutcome()).isEqualTo("NUDGE_SENT");
        assertThat(response.getHttpStatus()).isEqualTo(204);
        assertThat(response.getCertificateXrefs()).containsExactly("crt-1");
    }

    @Test
    void intuneRejectionBecomesRejectedOutcomeWithoutFailingDelivery() {
        when(profileRegistry.require("intune-primary", DevicePlatformType.INTUNE)).thenReturn(profile);
        when(sessionProvider.open(profile)).thenReturn(new IntuneSession("token"));
        doThrow(new PermanentAgentException("DEVICE_NOT_FOUND", "unknown"))
                .when(graphClient).syncDevice("token", "11111111-1111-1111-1111-111111111111");

        processor().process(message("INTUNE"), context);

        IotDeviceSyncResponse response = capture();
        assertThat(response.getOutcome()).isEqualTo("INTUNE_REJECTED");
        assertThat(response.getErrorCode()).isEqualTo("DEVICE_NOT_FOUND");
    }

    @Test
    void intuneRejectionPreservesTheGraphHttpStatus() {
        when(profileRegistry.require("intune-primary", DevicePlatformType.INTUNE)).thenReturn(profile);
        when(sessionProvider.open(profile)).thenReturn(new IntuneSession("token"));
        doThrow(new PermanentAgentException("PERMISSION_DENIED", "forbidden",
                HttpClientErrorException.create(
                        HttpStatus.FORBIDDEN, "Forbidden", null, null, null)))
                .when(graphClient).syncDevice("token", "11111111-1111-1111-1111-111111111111");

        processor().process(message("INTUNE"), context);

        IotDeviceSyncResponse response = capture();
        assertThat(response.getOutcome()).isEqualTo("INTUNE_REJECTED");
        assertThat(response.getHttpStatus()).isEqualTo(403);
    }

    @Test
    void transientFailureBecomesUnavailableOutcome() {
        when(profileRegistry.require("intune-primary", DevicePlatformType.INTUNE)).thenReturn(profile);
        when(sessionProvider.open(profile)).thenReturn(new IntuneSession("token"));
        doThrow(new TransientAgentException("PLATFORM_THROTTLED", "429"))
                .when(graphClient).syncDevice("token", "11111111-1111-1111-1111-111111111111");

        processor().process(message("INTUNE"), context);

        assertThat(capture().getOutcome()).isEqualTo("INTUNE_UNAVAILABLE");
    }

    @Test
    void nonIntuneProviderIsSkippedUnsupported() {
        processor().process(message("JAMF"), context);

        verify(graphClient, never()).syncDevice(any(), any());
        assertThat(capture().getOutcome()).isEqualTo("SKIPPED_UNSUPPORTED");
    }
}
