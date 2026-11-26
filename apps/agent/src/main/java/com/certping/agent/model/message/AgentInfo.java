// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * What this agent is and what it can do, sent with the heartbeat for the Agents page.
 *
 * <p>Descriptive only. Nothing here may carry a secret: no token, no key, no credential, no URL
 * that could hold one. The proxy is reported as a yes or no, never its address.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AgentInfo {

    /** The agent build version, or "dev" when the build does not say. */
    private String version;
    private String hostname;
    /** os.name and os.arch, for example "Linux aarch64". */
    private String os;
    private String javaVersion;
    /** LOCAL, AZURE_KV, AWS_SECRETS_MANAGER or GCP_SECRET_MANAGER. */
    private String secretStore;
    private Integer maxConcurrentJobs;
    /** True when HTTPS_PROXY is set for the connection to the server. */
    private Boolean proxyConfigured;
    /** True for the agent shipped with the server. */
    private Boolean bundled;
    private Capabilities capabilities;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Capabilities {
        private List<String> deploymentTargets;
        private List<String> discoveryTargets;
        private List<String> dnsProviders;
    }
}
