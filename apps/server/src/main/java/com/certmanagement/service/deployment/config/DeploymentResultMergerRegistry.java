// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import com.certmanagement.messaging.model.TargetType;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Spring-discovered registry of {@link DeploymentResultMerger}s keyed by {@link TargetType}.
 *
 * <p>Adapters that don't yet have a merger return {@link Optional#empty()} — callers should
 * treat that as "no result merging for this provider".
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeploymentResultMergerRegistry {

    private final List<DeploymentResultMerger> mergers;

    private final Map<TargetType, DeploymentResultMerger> byType = new EnumMap<>(TargetType.class);

    @PostConstruct
    void index() {
        for (DeploymentResultMerger merger : mergers) {
            for (TargetType type : merger.supportedTargetTypes()) {
                DeploymentResultMerger existing = byType.put(type, merger);
                if (existing != null && existing != merger) {
                    throw new IllegalStateException(
                            "Multiple DeploymentResultMergers registered for " + type
                                    + ": " + existing.getClass().getSimpleName()
                                    + " and " + merger.getClass().getSimpleName());
                }
            }
        }
        log.info("Registered {} deployment result mergers covering {} target types",
                mergers.size(), byType.size());
    }

    public Optional<DeploymentResultMerger> find(TargetType type) {
        return Optional.ofNullable(byType.get(type));
    }
}
