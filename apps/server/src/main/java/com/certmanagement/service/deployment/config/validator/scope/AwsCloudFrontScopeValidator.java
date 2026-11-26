// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireOneOf;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code AWS_CLOUDFRONT} credential scope:
 * {@code { authMode, roleArn?, externalId?, distributionId }}.
 *
 * <p>The adapter forces {@code us-east-1} for ACM (CloudFront's only supported region), so
 * {@code region} is not a configurable field.
 */
@Component
public class AwsCloudFrontScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AWS_CLOUDFRONT";
    private static final Set<String> AUTH_MODES = Set.of("STATIC_KEYS", "ASSUME_ROLE", "INSTANCE_PROFILE");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AWS_CLOUDFRONT);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        String authMode = requireOneOf(configJson, "authMode", AUTH_MODES, CTX);
        if ("ASSUME_ROLE".equals(authMode)) {
            requireString(configJson, "roleArn", CTX);
        }
        requireString(configJson, "distributionId", CTX);
    }
}
