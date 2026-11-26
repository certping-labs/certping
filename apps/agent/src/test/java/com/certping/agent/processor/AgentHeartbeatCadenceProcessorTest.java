// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.health.HeartbeatCadenceState;
import com.certping.agent.model.message.AgentHeartbeatCadenceUpdateMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AgentHeartbeatCadenceProcessorTest {

    @Mock
    private HeartbeatCadenceState cadenceState;
    @Mock
    private InboundContext context;

    @Test
    void process_matchingOrganizationId_appliesCadence() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("organization-id-1");
        properties.setOrganizationSlug("organization-slug-1");

        AgentHeartbeatCadenceProcessor processor = new AgentHeartbeatCadenceProcessor(properties, cadenceState);
        AgentHeartbeatCadenceUpdateMessage message = new AgentHeartbeatCadenceUpdateMessage();
        message.setOrganizationId("organization-id-1");
        message.setHeartbeatCadenceMinutes(7);

        processor.process(message, context);

        verify(cadenceState).updateFromMinutes(7);
        verify(context).complete();
    }

    @Test
    void process_nonMatchingOrganizationId_doesNotApplyCadence() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("organization-id-1");
        properties.setOrganizationSlug("organization-slug-1");

        AgentHeartbeatCadenceProcessor processor = new AgentHeartbeatCadenceProcessor(properties, cadenceState);
        AgentHeartbeatCadenceUpdateMessage message = new AgentHeartbeatCadenceUpdateMessage();
        message.setOrganizationId("organization-id-2");
        message.setHeartbeatCadenceMinutes(7);

        processor.process(message, context);

        verify(cadenceState, never()).updateFromMinutes(7);
        verify(context).complete();
    }
}
