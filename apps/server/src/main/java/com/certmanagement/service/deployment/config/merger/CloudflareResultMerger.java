// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentResultMerger;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Merges Cloudflare's cert ID into the envelope's {@code result}.
 *
 * <p>Agent-returned shape: {@code { "certId": "..." }}.
 * The merger overlays the incoming {@code certId} onto the existing result.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CloudflareResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.CLOUDFLARE_EDGE);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        JsonNode certIdNode = fromAgent.get("certId");
        if (certIdNode == null || !certIdNode.isString() || certIdNode.asString().isBlank()) {
            log.warn("CloudflareResultMerger: agent JSON missing 'certId' — skipping");
            return current;
        }

        ObjectNode result = current != null && current.isObject()
                ? ((ObjectNode) current).deepCopy()
                : objectMapper.createObjectNode();
        result.put("certId", certIdNode.asString());
        return result;
    }
}
