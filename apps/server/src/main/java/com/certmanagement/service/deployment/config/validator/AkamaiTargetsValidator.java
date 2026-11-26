// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Validates {@code AKAMAI_CPS} targets.
 *
 * <p>All configuration (enrollment ID, network, host) lives in the credential scope.
 * Targets are empty ({@code {}}) — this validator accepts any object and returns {@code {}}.
 */
@Component
@RequiredArgsConstructor
public class AkamaiTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AKAMAI_CPS);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() { return SUPPORTED; }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        ObjectNode root = objectMapper.createObjectNode();
        return root;
    }
}
