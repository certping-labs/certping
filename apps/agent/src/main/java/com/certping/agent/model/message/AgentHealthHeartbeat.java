// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

/**
 * Periodic outbound heartbeat published by the agent.
 */
@Data
@Builder
public class AgentHealthHeartbeat {
    private String organizationId;
    private Boolean listening;
    private String respondedAt;
    /** Effective heartbeat interval in minutes (1–60), derived from in-memory cadence state. */
    private Integer heartbeatCadenceMinutes;
    /** Which CAs this agent can issue from (metadata only, never a key). Null when it could not be built. */
    private CaStatus caStatus;
    /** What this agent is and can do, for the Agents page (no secrets). Null when it could not be built. */
    private AgentInfo agentInfo;
}
