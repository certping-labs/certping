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

/** Spring-discovered registry of {@link DeploymentScopeValidator}s keyed by {@link TargetType}. */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeploymentScopeValidatorRegistry {

    private final List<DeploymentScopeValidator> validators;

    private final Map<TargetType, DeploymentScopeValidator> byType = new EnumMap<>(TargetType.class);

    @PostConstruct
    void index() {
        for (DeploymentScopeValidator validator : validators) {
            for (TargetType type : validator.supportedTargetTypes()) {
                DeploymentScopeValidator existing = byType.put(type, validator);
                if (existing != null && existing != validator) {
                    throw new IllegalStateException(
                            "Multiple DeploymentScopeValidators registered for " + type
                                    + ": " + existing.getClass().getSimpleName()
                                    + " and " + validator.getClass().getSimpleName());
                }
            }
        }
        log.info("Registered {} deployment scope validators covering {} target types",
                validators.size(), byType.size());
    }

    public Optional<DeploymentScopeValidator> find(TargetType type) {
        return Optional.ofNullable(byType.get(type));
    }
}
