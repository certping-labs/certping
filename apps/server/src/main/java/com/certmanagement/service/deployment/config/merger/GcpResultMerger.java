// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentResultMerger;
import tools.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Merges agent-returned GCP deployment results into the envelope's {@code result}.
 *
 * <p>GCP adapters return a structured object — typically
 * {@code { certificateName, appliedEntries|appliedProxies, ... }}. We accept any
 * non-empty JSON object and replace {@code result} wholesale.
 */
@Slf4j
@Component
public class GcpResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(
            TargetType.GCP_CERT_MANAGER,
            TargetType.GCP_ALB,
            TargetType.GCP_PROXY_NLB,
            TargetType.GCP_API_GW,
            TargetType.GCP_CLOUD_CDN);

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        if (fromAgent == null || !fromAgent.isObject() || fromAgent.isEmpty()) {
            log.warn("GcpResultMerger: agent JSON must be a non-empty object — skipping");
            return current;
        }
        return fromAgent;
    }
}
