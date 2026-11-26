// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.InboundConsumerLifecycle;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.AgentHealthHeartbeat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentHeartbeatPublisherTest {

    @Mock private AgentMessageSender sender;
    @Mock private InboundConsumerLifecycle inboundConsumer;
    @Mock private HeartbeatCadenceState cadenceStateMock;

    @Test
    void publishHeartbeat_allProcessorsRunning_sendsListeningTrue() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("organization-id-1");
        properties.setOrganizationSlug("organization-1");
        HeartbeatCadenceState cadenceState = new HeartbeatCadenceState(properties);

        when(inboundConsumer.isRunning()).thenReturn(true);

        AgentHeartbeatPublisher publisher = new AgentHeartbeatPublisher(
                properties,
                cadenceState,
                sender,
                inboundConsumer);

        publisher.publishHeartbeat();

        ArgumentCaptor<AgentHealthHeartbeat> captor = ArgumentCaptor.forClass(AgentHealthHeartbeat.class);
        verify(sender).sendHealthHeartbeat(captor.capture());
        AgentHealthHeartbeat heartbeat = captor.getValue();
        assertThat(heartbeat.getOrganizationId()).isEqualTo("organization-id-1");
        assertThat(heartbeat.getListening()).isTrue();
        assertThat(heartbeat.getRespondedAt()).isNotBlank();
        assertThat(heartbeat.getHeartbeatCadenceMinutes()).isEqualTo(5);
    }

    @Test
    void publishHeartbeat_cadenceNotDue_skipsSend() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("org");
        HeartbeatCadenceState cadenceState = new HeartbeatCadenceState(properties);
        cadenceState.markPublishedNow();

        AgentHeartbeatPublisher publisher = new AgentHeartbeatPublisher(
                properties,
                cadenceState,
                sender,
                inboundConsumer);

        publisher.publishHeartbeat();

        verify(sender, never()).sendHealthHeartbeat(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void publishHeartbeat_subOneMinuteInterval_clampsCadenceToOneMinute() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("org");

        when(cadenceStateMock.shouldPublishNow()).thenReturn(true);
        when(cadenceStateMock.getHeartbeatIntervalMs()).thenReturn(30_000L);

        when(inboundConsumer.isRunning()).thenReturn(true);

        AgentHeartbeatPublisher publisher = new AgentHeartbeatPublisher(
                properties,
                cadenceStateMock,
                sender,
                inboundConsumer);

        publisher.publishHeartbeat();

        ArgumentCaptor<AgentHealthHeartbeat> captor = ArgumentCaptor.forClass(AgentHealthHeartbeat.class);
        verify(sender).sendHealthHeartbeat(captor.capture());
        assertThat(captor.getValue().getHeartbeatCadenceMinutes()).isEqualTo(1);
    }

    @Test
    void publishHeartbeat_overSixtyMinuteInterval_clampsCadenceToSixtyMinutes() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("org");

        when(cadenceStateMock.shouldPublishNow()).thenReturn(true);
        when(cadenceStateMock.getHeartbeatIntervalMs()).thenReturn(120L * 60_000L);

        when(inboundConsumer.isRunning()).thenReturn(true);

        AgentHeartbeatPublisher publisher = new AgentHeartbeatPublisher(
                properties,
                cadenceStateMock,
                sender,
                inboundConsumer);

        publisher.publishHeartbeat();

        ArgumentCaptor<AgentHealthHeartbeat> captor = ArgumentCaptor.forClass(AgentHealthHeartbeat.class);
        verify(sender).sendHealthHeartbeat(captor.capture());
        assertThat(captor.getValue().getHeartbeatCadenceMinutes()).isEqualTo(60);
    }

    @Test
    void publishHeartbeat_carriesCaStatus_andGoesOutEarlyWhenTheAccountChanged() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("org");
        HeartbeatCadenceState cadenceState = new HeartbeatCadenceState(properties);
        cadenceState.markPublishedNow();
        CaStatusReporter reporter = org.mockito.Mockito.mock(CaStatusReporter.class);
        com.certping.agent.model.message.CaStatus status = new com.certping.agent.model.message.CaStatus();
        when(reporter.changedSinceLastReport()).thenReturn(true);
        when(reporter.current()).thenReturn(status);
        when(inboundConsumer.isRunning()).thenReturn(true);

        new AgentHeartbeatPublisher(properties, cadenceState, sender, inboundConsumer, reporter).publishHeartbeat();

        ArgumentCaptor<AgentHealthHeartbeat> captor = ArgumentCaptor.forClass(AgentHealthHeartbeat.class);
        verify(sender).sendHealthHeartbeat(captor.capture());
        assertThat(captor.getValue().getCaStatus()).isSameAs(status);
    }

    @Test
    void publishHeartbeat_caStatusFailure_stillSendsHeartbeat() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("org");
        HeartbeatCadenceState cadenceState = new HeartbeatCadenceState(properties);
        CaStatusReporter reporter = org.mockito.Mockito.mock(CaStatusReporter.class);
        when(reporter.current()).thenThrow(new IllegalStateException("boom"));
        when(inboundConsumer.isRunning()).thenReturn(true);

        new AgentHeartbeatPublisher(properties, cadenceState, sender, inboundConsumer, reporter).publishHeartbeat();

        ArgumentCaptor<AgentHealthHeartbeat> captor = ArgumentCaptor.forClass(AgentHealthHeartbeat.class);
        verify(sender).sendHealthHeartbeat(captor.capture());
        assertThat(captor.getValue().getCaStatus()).isNull();
    }
}
