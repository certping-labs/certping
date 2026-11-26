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
 * Merges agent-returned Azure Key Vault import result into the envelope's {@code result}.
 *
 * <p>Agent result shape (flat): {@code {"certificateName":"my-cert","version":"abc123"}}.
 * The merger overlays {@code certificateName} and {@code version} onto the stored result.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AzureKvNameResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AZURE_KV);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        JsonNode nameNode = fromAgent.get("certificateName");
        if (nameNode == null || !nameNode.isString() || nameNode.asString().isBlank()) {
            log.warn("AzureKvNameResultMerger: agent JSON missing 'certificateName' — skipping");
            return current;
        }
        ObjectNode result = current != null && current.isObject()
                ? ((ObjectNode) current).deepCopy()
                : objectMapper.createObjectNode();
        result.put("certificateName", nameNode.asString());

        JsonNode versionNode = fromAgent.get("version");
        if (versionNode != null && versionNode.isString() && !versionNode.asString().isBlank()) {
            result.put("version", versionNode.asString());
        }
        return result;
    }
}
