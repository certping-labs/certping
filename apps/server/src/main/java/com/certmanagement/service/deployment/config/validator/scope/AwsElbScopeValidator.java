// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireNonEmptyArray;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireOneOf;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code AWS_ALB} / {@code AWS_NLB} credential scope:
 * {@code { authMode, region, roleArn?, externalId?, listeners[] }}.
 */
@Component
public class AwsElbScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AWS_ALB/AWS_NLB";
    private static final Set<String> AUTH_MODES = Set.of("STATIC_KEYS", "ASSUME_ROLE", "INSTANCE_PROFILE");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AWS_ALB, TargetType.AWS_NLB);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        String authMode = requireOneOf(configJson, "authMode", AUTH_MODES, CTX);
        requireString(configJson, "region", CTX);
        if ("ASSUME_ROLE".equals(authMode)) {
            requireString(configJson, "roleArn", CTX);
        }
        requireNonEmptyArray(configJson, "listeners", CTX);
    }
}
