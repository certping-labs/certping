// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

/** Names shared by the agent gateway, the queue workers and the agent's HTTP transport. */
public final class AgentGatewayHeaders {

    /** Base path of the gateway. Authenticated by agent or internal bearer tokens, never by user JWTs. */
    public static final String BASE_PATH = "/api/v1/agent-gateway";

    /**
     * Application property the gateway stamps on every message an agent sends, holding the
     * organization of the token that sent it. Any value the agent supplied is overwritten.
     */
    public static final String ORGANIZATION_PROPERTY = "AuthenticatedOrganizationId";

    /**
     * Application property the gateway stamps on every message an agent sends, holding the id of the
     * agent token that sent it. Any value the agent supplied is overwritten.
     */
    public static final String AGENT_TOKEN_PROPERTY = "AuthenticatedAgentTokenId";

    /**
     * Application property on a command meant for one agent only, holding that agent's token id. Other
     * agents of the organization do not receive it. An agent can only target itself (its retries).
     */
    public static final String TARGET_AGENT_TOKEN_PROPERTY = "TargetAgentTokenId";

    private AgentGatewayHeaders() {
    }
}
