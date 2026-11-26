// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The uniform shape of {@code cert_deployment_config.config}:
 * <pre>
 * {
 *   "targets": { ...UI-driven intent... },
 *   "result":  { ...adapter-returned state... }
 * }
 * </pre>
 *
 * Helpers parse and emit this envelope. Per-provider adapters define what goes inside
 * {@code targets} and {@code result}.
 *
 * <p>Note: the legacy Kubernetes flat shape ({@code {authProvider, clusterName, nsMaps}})
 * is intentionally <em>not</em> wrapped here — Kubernetes persistence remains owned by
 * {@link com.certmanagement.service.deployment.CertDeploymentConfigService#validateAndUpsertKubernetesConfig}
 * pending its own refactor.
 */
public record DeploymentConfigEnvelope(JsonNode targets, JsonNode result) {

    public static DeploymentConfigEnvelope empty(ObjectMapper mapper) {
        return new DeploymentConfigEnvelope(mapper.createObjectNode(), mapper.createObjectNode());
    }

    public static DeploymentConfigEnvelope read(ObjectMapper mapper, String json) {
        try {
            if (json == null || json.isBlank()) {
                return empty(mapper);
            }
            JsonNode root = mapper.readTree(json);
            JsonNode targets = root.has("targets") && root.get("targets").isObject()
                    ? root.get("targets")
                    : mapper.createObjectNode();
            JsonNode result = root.has("result") && root.get("result").isObject()
                    ? root.get("result")
                    : mapper.createObjectNode();
            return new DeploymentConfigEnvelope(targets, result);
        } catch (Exception e) {
            return empty(mapper);
        }
    }

    public String write(ObjectMapper mapper) {
        try {
            ObjectNode root = mapper.createObjectNode();
            root.set("targets", targets != null ? targets : mapper.createObjectNode());
            root.set("result", result != null ? result : mapper.createObjectNode());
            return mapper.writeValueAsString(root);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize deployment config envelope", e);
        }
    }

    public DeploymentConfigEnvelope withResult(JsonNode newResult) {
        return new DeploymentConfigEnvelope(this.targets, newResult);
    }

    public DeploymentConfigEnvelope withTargets(JsonNode newTargets) {
        return new DeploymentConfigEnvelope(newTargets, this.result);
    }
}
