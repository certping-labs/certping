// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.merger;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentResultMerger;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Merges Akamai CPS deployment result. Sets {@code lastChange} from the agent payload and
 * appends the prior {@code lastChange} (if present) to {@code history[]}, capped at 5.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AkamaiResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AKAMAI_CPS);
    private static final int HISTORY_CAP = 5;

    private final ObjectMapper objectMapper;

    @Override public Set<TargetType> supportedTargetTypes() { return SUPPORTED; }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        JsonNode incomingLastChange = fromAgent.get("lastChange");
        if (incomingLastChange == null || !incomingLastChange.isObject()) {
            log.warn("AkamaiResultMerger: agent JSON missing 'lastChange' object — skipping");
            return current;
        }
        ObjectNode result = current != null && current.isObject()
                ? ((ObjectNode) current).deepCopy()
                : objectMapper.createObjectNode();

        // Move existing lastChange into history (front of the array, capped).
        JsonNode priorLastChange = result.has("lastChange") && result.get("lastChange").isObject()
                ? result.get("lastChange").deepCopy() : null;
        ArrayNode history = result.has("history") && result.get("history").isArray()
                ? ((ArrayNode) result.get("history")).deepCopy()
                : objectMapper.createArrayNode();
        if (priorLastChange != null) {
            ArrayNode rebuilt = objectMapper.createArrayNode();
            rebuilt.add(priorLastChange);
            int kept = 1;
            for (JsonNode entry : history) {
                if (kept >= HISTORY_CAP) break;
                rebuilt.add(entry);
                kept++;
            }
            history = rebuilt;
        }

        result.set("lastChange", incomingLastChange);
        result.set("history", history);
        return result;
    }
}
