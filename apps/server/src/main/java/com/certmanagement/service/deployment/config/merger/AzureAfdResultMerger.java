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
 * Merges Azure Front Door deployment result into the envelope's {@code result}.
 *
 * <p>Agent-returned shape:
 * {@code {"certificateName": "...", "secretName": "..."}}.
 *
 * <p>Both fields are overlaid on every deploy.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AzureAfdResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AZURE_AFD);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        if (fromAgent == null || !fromAgent.isObject()) {
            log.warn("AzureAfdResultMerger: agent JSON missing/non-object — skipping");
            return current;
        }

        ObjectNode result = current != null && current.isObject()
                ? ((ObjectNode) current).deepCopy()
                : objectMapper.createObjectNode();

        JsonNode certName = fromAgent.get("certificateName");
        if (certName != null && certName.isString() && !certName.asString().isBlank()) {
            result.put("certificateName", certName.asString());
        }

        JsonNode secretName = fromAgent.get("secretName");
        if (secretName != null && secretName.isString() && !secretName.asString().isBlank()) {
            result.put("secretName", secretName.asString());
        }

        return result;
    }
}
