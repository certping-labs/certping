// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * One agent on the Agents page: its token, whether it is online, and what it last reported about
 * itself. Built field by field from typed, sanitized values; it has no field that could hold a
 * secret, so none can be returned.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record AgentView(
        String agentId,
        String name,
        String tokenPrefix,
        String tokenCreatedAt,
        String tokenExpiresAt,
        boolean revoked,
        String status,
        String lastSeenAt,
        String version,
        String hostname,
        String os,
        String javaVersion,
        String secretStore,
        Integer maxConcurrentJobs,
        Boolean proxyConfigured,
        boolean bundled,
        Acme acme,
        Boolean globalsignConfigured,
        Capabilities capabilities) {

    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record Acme(String directoryUrl, String environment, String contactEmail) {
    }

    public record Capabilities(List<String> deploymentTargets, List<String> discoveryTargets,
                               List<String> dnsProviders) {
    }

    /** The GET /api/v1/agents body. */
    public record AgentList(List<AgentView> agents) {
    }
}
