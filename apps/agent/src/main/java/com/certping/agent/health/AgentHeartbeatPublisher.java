// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.config.InboundConsumerLifecycle;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.AgentHealthHeartbeat;
import com.certping.agent.model.message.AgentInfo;
import com.certping.agent.model.message.CaStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Slf4j
@Component
public class AgentHeartbeatPublisher {

    private final AgentProperties properties;
    private final HeartbeatCadenceState cadenceState;
    private final AgentMessageSender sender;
    private final InboundConsumerLifecycle inboundConsumer;
    /** Null in tests that do not cover the CA status. */
    private final CaStatusReporter caStatusReporter;
    /** Null in tests that do not cover the agent info. */
    private final AgentInfoReporter agentInfoReporter;

    public AgentHeartbeatPublisher(AgentProperties properties, HeartbeatCadenceState cadenceState,
                                   AgentMessageSender sender, InboundConsumerLifecycle inboundConsumer) {
        this(properties, cadenceState, sender, inboundConsumer, null, null);
    }

    public AgentHeartbeatPublisher(AgentProperties properties, HeartbeatCadenceState cadenceState,
                                   AgentMessageSender sender, InboundConsumerLifecycle inboundConsumer,
                                   CaStatusReporter caStatusReporter) {
        this(properties, cadenceState, sender, inboundConsumer, caStatusReporter, null);
    }

    @Autowired
    public AgentHeartbeatPublisher(AgentProperties properties, HeartbeatCadenceState cadenceState,
                                   AgentMessageSender sender, InboundConsumerLifecycle inboundConsumer,
                                   CaStatusReporter caStatusReporter, AgentInfoReporter agentInfoReporter) {
        this.properties = properties;
        this.cadenceState = cadenceState;
        this.sender = sender;
        this.inboundConsumer = inboundConsumer;
        this.caStatusReporter = caStatusReporter;
        this.agentInfoReporter = agentInfoReporter;
    }

    @Scheduled(
            initialDelayString = "${agent.health.scheduler-tick-ms:5000}",
            fixedDelayString = "${agent.health.scheduler-tick-ms:5000}")
    public void publishHeartbeat() {
        // A new ACME account is reported at the next tick rather than at the next due heartbeat.
        boolean caChanged = caStatusReporter != null && caStatusReporter.changedSinceLastReport();
        if (!caChanged && !cadenceState.shouldPublishNow()) {
            return;
        }

        boolean listening = inboundConsumer.isRunning();

        long intervalMs = cadenceState.getHeartbeatIntervalMs();
        int cadenceMinutes = (int) (intervalMs / 60_000L);
        if (cadenceMinutes < 1) {
            cadenceMinutes = 1;
        } else if (cadenceMinutes > 60) {
            cadenceMinutes = 60;
        }

        AgentHealthHeartbeat heartbeat = AgentHealthHeartbeat.builder()
                .organizationId(properties.getOrganizationId())
                .listening(listening)
                .respondedAt(OffsetDateTime.now(ZoneOffset.UTC).toString())
                .heartbeatCadenceMinutes(cadenceMinutes)
                .caStatus(caStatus())
                .agentInfo(agentInfo())
                .build();

        sender.sendHealthHeartbeat(heartbeat);
        cadenceState.markPublishedNow();
        log.debug("Published AGENT_HEALTH_HEARTBEAT organizationId={} listening={} intervalMs={} cadenceMinutes={}",
                properties.getOrganizationId(), listening, intervalMs, cadenceMinutes);
    }

    private AgentInfo agentInfo() {
        if (agentInfoReporter == null) {
            return null;
        }
        try {
            return agentInfoReporter.current();
        } catch (RuntimeException e) {
            log.warn("Could not build the agent info for the heartbeat: {}", e.getMessage());
            return null;
        }
    }

    private CaStatus caStatus() {
        if (caStatusReporter == null) {
            return null;
        }
        try {
            return caStatusReporter.current();
        } catch (RuntimeException e) {
            // The heartbeat matters more than the CA status: send it without.
            log.warn("Could not build the CA status for the heartbeat: {}", e.getMessage());
            return null;
        }
    }
}
