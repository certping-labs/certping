// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Periodic outbound report on every CA connector this agent is configured for.
 *
 * <p>Deliberately CA-agnostic. Nothing in this payload or its children names EJBCA: a Smallstep
 * or DigiCert One connector fills the same shape, so the server parses one schema forever and
 * adding a CA is an agent-side change only.
 *
 * <p>Sibling of {@link AgentHealthHeartbeat}: the heartbeat answers "is the agent alive", this
 * answers "can it actually issue certificates, and if not, why not".
 */
@Data
@Builder
public class CaHealthReport {

    /**
     * Schema version. Present so the server can reject or adapt to a payload it does not
     * understand rather than silently mis-parsing one.
     */
    private Integer reportVersion;

    private String organizationId;
    private String respondedAt;

    /** One entry per configured CA connector. Empty when the agent has no CA configured. */
    private List<CaConnectorHealth> connectors;
}
