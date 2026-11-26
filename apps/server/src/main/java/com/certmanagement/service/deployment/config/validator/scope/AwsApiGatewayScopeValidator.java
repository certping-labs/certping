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
 * Validates {@code AWS_API_GW_REST} / {@code AWS_API_GW_HTTP} credential scope:
 * {@code { authMode, region, roleArn?, externalId?, customDomains[] }}.
 */
@Component
public class AwsApiGatewayScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AWS_API_GW";
    private static final Set<String> AUTH_MODES = Set.of("STATIC_KEYS", "ASSUME_ROLE", "INSTANCE_PROFILE");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AWS_API_GW_REST, TargetType.AWS_API_GW_HTTP);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        String authMode = requireOneOf(configJson, "authMode", AUTH_MODES, CTX);
        requireString(configJson, "region", CTX);
        if ("ASSUME_ROLE".equals(authMode)) {
            requireString(configJson, "roleArn", CTX);
        }
        requireNonEmptyArray(configJson, "customDomains", CTX);
    }
}
