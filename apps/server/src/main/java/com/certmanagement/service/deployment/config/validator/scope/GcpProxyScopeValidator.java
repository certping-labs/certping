// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalString;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireOneOf;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code GCP_ALB} / {@code GCP_API_GW} / {@code GCP_CLOUD_CDN} credential scope:
 * {@code { authMode, projectId, location, impersonateServiceAccount?, targetProxy }}.
 */
@Component
public class GcpProxyScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "GCP_ALB/API_GW/CLOUD_CDN";
    private static final Set<String> AUTH_MODES = Set.of(
            "SERVICE_ACCOUNT_KEY", "WORKLOAD_IDENTITY", "IMPERSONATE_SERVICE_ACCOUNT");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.GCP_ALB, TargetType.GCP_API_GW, TargetType.GCP_CLOUD_CDN);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        String authMode = requireOneOf(configJson, "authMode", AUTH_MODES, CTX);
        requireString(configJson, "projectId", CTX);
        requireString(configJson, "location", CTX);
        if ("IMPERSONATE_SERVICE_ACCOUNT".equals(authMode)) {
            requireString(configJson, "impersonateServiceAccount", CTX);
        } else {
            optionalString(configJson, "impersonateServiceAccount");
        }
        requireString(configJson, "targetProxy", CTX);
    }
}
