// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Received from cert-agent-outbound with MessageType=AGENT_HEALTH_HEARTBEAT.
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentHealthHeartbeat {
    private String organizationId;
    private Boolean listening;
    private String respondedAt;
    /**
     * Agent-reported effective cadence in minutes. When it differs from the value in
     * {@code organizations.agent_heartbeat_cadence_minutes}, the manager publishes
     * {@code AGENT_HEARTBEAT_CADENCE_UPDATE} to align the agent with the DB.
     */
    private Integer heartbeatCadenceMinutes;
    /** Optional: which CAs the agent can issue from. Older agents do not send it. */
    private AgentCaStatus caStatus;
    /** Optional: what the agent is and can do, for the Agents page. Older agents do not send it. */
    private AgentInfo agentInfo;
}
