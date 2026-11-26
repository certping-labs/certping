// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.health.HeartbeatCadenceState;
import com.certping.agent.model.message.AgentHeartbeatCadenceUpdateMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AgentHeartbeatCadenceProcessor {

    private final AgentProperties properties;
    private final HeartbeatCadenceState cadenceState;

    public void process(AgentHeartbeatCadenceUpdateMessage message, InboundContext context) {
        if (message.getOrganizationId() == null || !message.getOrganizationId().equals(properties.getOrganizationId())) {
            log.warn("Ignoring AGENT_HEARTBEAT_CADENCE_UPDATE for organizationId={} configuredOrganizationId={}",
                    message.getOrganizationId(), properties.getOrganizationId());
            context.complete();
            return;
        }

        Integer cadenceMinutes = message.getHeartbeatCadenceMinutes();
        if (cadenceMinutes == null || cadenceMinutes < 1 || cadenceMinutes > 60) {
            log.warn("Ignoring AGENT_HEARTBEAT_CADENCE_UPDATE invalid cadence={} organizationId={}",
                    cadenceMinutes, message.getOrganizationId());
            context.complete();
            return;
        }

        cadenceState.updateFromMinutes(cadenceMinutes);
        context.complete();
        log.info("Applied AGENT_HEARTBEAT_CADENCE_UPDATE organizationId={} cadenceMinutes={} intervalMs={}",
                message.getOrganizationId(), cadenceMinutes, cadenceState.getHeartbeatIntervalMs());
    }
}
