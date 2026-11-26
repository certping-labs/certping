// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves the appropriate {@link DeploymentAdapter} for a given target type.
 *
 * Adapters register themselves by annotating with {@link DeploymentAdapterFor} — no
 * switch statement is required here. Spring injects all {@link DeploymentAdapter} beans
 * and this factory builds the lookup map at startup.
 */
@Slf4j
@Component
public class DeploymentAdapterFactory {

    private final Map<TargetType, DeploymentAdapter> adapters;

    public DeploymentAdapterFactory(List<DeploymentAdapter> adapterList) {
        adapters = new EnumMap<>(TargetType.class);
        for (DeploymentAdapter adapter : adapterList) {
            DeploymentAdapterFor annotation =
                    adapter.getClass().getAnnotation(DeploymentAdapterFor.class);
            if (annotation != null) {
                for (TargetType targetType : annotation.value()) {
                    adapters.put(targetType, adapter);
                    log.debug("Registered adapter {} for targetType={}",
                            adapter.getClass().getSimpleName(), targetType);
                }
            }
        }
        log.info("DeploymentAdapterFactory initialised with {} target type mappings", adapters.size());
    }

    /** The target types this agent can deploy to, in enum order. */
    public java.util.Set<TargetType> supportedTargetTypes() {
        return java.util.Collections.unmodifiableSet(java.util.EnumSet.copyOf(
                adapters.isEmpty() ? java.util.EnumSet.noneOf(TargetType.class) : adapters.keySet()));
    }

    public DeploymentAdapter create(TargetType targetType) {
        if (targetType == null) {
            throw new PermanentAgentException("DEPLOY_UNKNOWN_TARGET",
                    "targetType is null in CERT_DEPLOYMENT message");
        }
        DeploymentAdapter adapter = adapters.get(targetType);
        if (adapter == null) {
            throw new PermanentAgentException("DEPLOY_UNKNOWN_TARGET",
                    "No deployment adapter registered for targetType: " + targetType);
        }
        return adapter;
    }
}
