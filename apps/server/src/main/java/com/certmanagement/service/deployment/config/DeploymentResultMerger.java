// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;

import java.util.Set;

/**
 * Per-provider strategy for merging an agent-returned deployment result
 * into the {@code result} side of {@link DeploymentConfigEnvelope}.
 *
 * <p>Implementations are auto-discovered by Spring and registered in
 * {@link DeploymentResultMergerRegistry}.
 */
public interface DeploymentResultMerger {

    /** Target types this merger handles. The registry will reject overlapping registrations. */
    Set<TargetType> supportedTargetTypes();

    /**
     * Merge agent-returned per-deployment JSON into the result side.
     *
     * @param current  the current {@code result} object (never null; may be empty)
     * @param fromAgent the JSON returned by the agent (raw, provider-shaped); never null/empty
     * @return the new {@code result} JsonNode to store. Return {@code null} or {@code current}
     *         to signal "no change". Returning a different node replaces {@code result} entirely.
     */
    JsonNode merge(JsonNode current, JsonNode fromAgent);
}
