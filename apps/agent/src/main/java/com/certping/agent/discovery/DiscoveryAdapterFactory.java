// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves the appropriate {@link DiscoveryAdapter} for a given target type.
 *
 * <p>Adapters register themselves by annotating with {@link DiscoveryAdapterFor} — no
 * switch statement is required here. Spring injects all {@link DiscoveryAdapter} beans
 * and this factory builds the lookup map at startup.
 */
@Slf4j
@Component
public class DiscoveryAdapterFactory {

    private final Map<TargetType, DiscoveryAdapter> adapters;

    public DiscoveryAdapterFactory(List<DiscoveryAdapter> adapterList) {
        adapters = new EnumMap<>(TargetType.class);
        for (DiscoveryAdapter adapter : adapterList) {
            DiscoveryAdapterFor annotation = adapter.getClass().getAnnotation(DiscoveryAdapterFor.class);
            if (annotation != null) {
                for (TargetType targetType : annotation.value()) {
                    adapters.put(targetType, adapter);
                    log.debug("Registered discovery adapter {} for targetType={}",
                            adapter.getClass().getSimpleName(), targetType);
                }
            }
        }
        log.info("DiscoveryAdapterFactory initialised with {} target type mappings", adapters.size());
    }

    /** The target types this agent can discover certificates on, in enum order. */
    public java.util.Set<TargetType> supportedTargetTypes() {
        return java.util.Collections.unmodifiableSet(java.util.EnumSet.copyOf(
                adapters.isEmpty() ? java.util.EnumSet.noneOf(TargetType.class) : adapters.keySet()));
    }

    public DiscoveryAdapter create(TargetType targetType) {
        if (targetType == null) {
            throw new PermanentAgentException("DISCOVERY_UNKNOWN_TARGET",
                    "targetType is null in CERT_DISCOVERY message");
        }
        DiscoveryAdapter adapter = adapters.get(targetType);
        if (adapter == null) {
            throw new PermanentAgentException("DISCOVERY_UNSUPPORTED_TARGET",
                    "No discovery adapter registered for targetType: " + targetType);
        }
        return adapter;
    }
}
