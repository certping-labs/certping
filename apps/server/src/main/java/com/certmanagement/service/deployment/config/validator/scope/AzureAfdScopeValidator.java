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
 * Validates {@code AZURE_AFD} credential scope:
 * {@code { authMode, tenantId, subscriptionId, resourceGroup, profileName, keyVaultUri,
 *         customDomains[] }}.
 *
 * <p>Per-cert {@code certificateName} (KV cert) and {@code secretName} (AFD Secret resource)
 * live in {@code targets}, so one AFD profile credential can host many independent certs.
 */
@Component
public class AzureAfdScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AZURE_AFD";
    private static final Set<String> AUTH_MODES = Set.of("SERVICE_PRINCIPAL", "WORKLOAD_IDENTITY");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AZURE_AFD);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);
        requireOneOf(configJson, "authMode", AUTH_MODES, CTX);
        requireString(configJson, "tenantId", CTX);
        requireString(configJson, "subscriptionId", CTX);
        requireString(configJson, "resourceGroup", CTX);
        requireString(configJson, "profileName", CTX);
        requireString(configJson, "keyVaultUri", CTX);
        requireNonEmptyArray(configJson, "customDomains", CTX);
    }
}
