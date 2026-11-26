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
 * Merges F5 BIG-IP deployment result into the envelope's {@code result}.
 *
 * <p>Agent-returned shape:
 * <pre>
 * {
 *   "certName": "cert-0001_v2",
 *   "keyName":  "cert-0001_v2",
 *   "version":  2,
 *   "profilesPatched": ["clientssl-api", "clientssl-www"],
 *   "lastSyncedAt": "ISO-8601"
 * }
 * </pre>
 *
 * <p>Single partition per credential, so the merger replaces wholesale (no partition keying).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class F5ResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.F5_BIGIP);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        if (fromAgent == null || !fromAgent.isObject()) {
            log.warn("F5ResultMerger: agent JSON missing/not-object — skipping");
            return current;
        }
        JsonNode certName = fromAgent.get("certName");
        if (certName == null || !certName.isString() || certName.asString().isBlank()) {
            log.warn("F5ResultMerger: agent JSON missing 'certName' — skipping");
            return current;
        }

        ObjectNode result = current != null && current.isObject()
                ? ((ObjectNode) current).deepCopy()
                : objectMapper.createObjectNode();

        result.put("certName", certName.asString());

        JsonNode keyName = fromAgent.get("keyName");
        if (keyName != null && keyName.isString() && !keyName.asString().isBlank()) {
            result.put("keyName", keyName.asString());
        }
        JsonNode version = fromAgent.get("version");
        if (version != null && version.isInt()) {
            result.put("version", version.asInt());
        }
        JsonNode profilesPatched = fromAgent.get("profilesPatched");
        if (profilesPatched != null && profilesPatched.isArray()) {
            result.set("profilesPatched", profilesPatched.deepCopy());
        }
        JsonNode lastSyncedAt = fromAgent.get("lastSyncedAt");
        if (lastSyncedAt != null && lastSyncedAt.isString() && !lastSyncedAt.asString().isBlank()) {
            result.put("lastSyncedAt", lastSyncedAt.asString());
        }
        return result;
    }
}
