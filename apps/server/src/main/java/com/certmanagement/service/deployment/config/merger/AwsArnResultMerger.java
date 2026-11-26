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
 * Merges agent-returned {@code {"arn": "..."}} for AWS deployment targets into
 * the envelope's {@code result} as {@code {"arn": "..."}}.
 *
 * <p>All AWS adapters emit flat {@code {"arn": "..."}} — no additional fields.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AwsArnResultMerger implements DeploymentResultMerger {

    private static final Set<TargetType> SUPPORTED = Set.of(
            TargetType.AWS_ACM,
            TargetType.AWS_ALB,
            TargetType.AWS_NLB,
            TargetType.AWS_API_GW_REST,
            TargetType.AWS_API_GW_HTTP,
            TargetType.AWS_CLOUDFRONT);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode merge(JsonNode current, JsonNode fromAgent) {
        JsonNode arnNode = fromAgent.get("arn");
        if (arnNode == null || !arnNode.isString() || arnNode.asString().isBlank()) {
            log.warn("AwsArnResultMerger: agent JSON missing 'arn' — skipping");
            return current;
        }
        ObjectNode result = current != null && current.isObject()
                ? ((ObjectNode) current).deepCopy()
                : objectMapper.createObjectNode();
        result.put("arn", arnNode.asString());
        return result;
    }
}
