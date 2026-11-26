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

/** Validates {@code AZURE_KV} credential scope: {@code { authMode, tenantId, vaultUri }}. */
@Component
public class AzureKvScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AZURE_KV";
    private static final Set<String> AUTH_MODES = Set.of("SERVICE_PRINCIPAL", "WORKLOAD_IDENTITY");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AZURE_KV);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        requireOneOf(configJson, "authMode", AUTH_MODES, CTX);
        requireString(configJson, "tenantId", CTX);
        requireString(configJson, "vaultUri", CTX);
    }
}
