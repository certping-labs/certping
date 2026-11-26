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
 * Merges Azure Application Gateway for Containers (AGC) deployment result.
 *
 * <p>Agent-returned shape ({@code AzureAgcDeploymentAdapter}):
 * {@code {"appliedSecrets": [{"namespace","secretName","resourceVersion"}], "clusterName":"...", "agcNamespace":"..."}}
 *
 * <p>Behaviour when populated:
 * <ul>
 *   <li>{@code appliedSecrets} is REPLACED on every deploy (agent returns the full set it touched).</li>
 *   <li>{@code clusterName} / {@code agcNamespace} are overlaid when textual + non-blank.</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AzureAgcResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AZURE_APP_GW_CONTAINERS);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        if (fromAgent == null || !fromAgent.isObject()) {
            log.warn("AzureAgcResultMerger: agent JSON missing/non-object — skipping");
            return current;
        }

        ObjectNode result = current != null && current.isObject()
                ? ((ObjectNode) current).deepCopy()
                : objectMapper.createObjectNode();

        JsonNode appliedSecrets = fromAgent.get("appliedSecrets");
        boolean changed = false;
        if (appliedSecrets != null && appliedSecrets.isArray() && !appliedSecrets.isEmpty()) {
            result.set("appliedSecrets", appliedSecrets.deepCopy());
            changed = true;
        } else {
            log.debug("AzureAgcResultMerger: 'appliedSecrets' missing/empty — preserving existing");
        }

        for (String field : new String[]{"clusterName", "agcNamespace"}) {
            JsonNode v = fromAgent.get(field);
            if (v != null && v.isString() && !v.asString().isBlank()) {
                result.put(field, v.asString());
                changed = true;
            }
        }

        return changed ? result : current;
    }
}
