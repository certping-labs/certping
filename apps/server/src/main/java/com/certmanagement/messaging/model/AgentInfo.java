// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * The {@code agentInfo} an agent sends with its heartbeat: what it is and what it can do.
 *
 * <p>Only the fields named here are read, stored and returned; anything else in the payload is
 * dropped on parsing, and {@link com.certmanagement.service.agent.AgentInfoSanitizer} checks the
 * values before they are stored. Whatever an agent sends, no secret reaches the database or an API
 * through this object.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentInfo {

    private String version;
    private String hostname;
    private String os;
    private String javaVersion;
    private String secretStore;
    private Integer maxConcurrentJobs;
    private Boolean proxyConfigured;
    private Boolean bundled;
    private Capabilities capabilities;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Capabilities {
        private List<String> deploymentTargets;
        private List<String> discoveryTargets;
        private List<String> dnsProviders;
    }
}
