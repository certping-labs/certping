// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalOneOf;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.optionalString;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireNonEmptyArray;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireObject;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireOneOf;
import static com.certmanagement.service.deployment.config.validator.scope.ScopeValidationUtils.requireString;

/**
 * Validates {@code AZURE_APP_GW_CONTAINERS} credential scope:
 * {@code { tenantId?, subscriptionId?, resourceGroup?, clusterAuthMode, clusterName,
 *         agcNamespace, apiStyle?, secretNamespaces[] }}.
 *
 * <p>Azure ARM identity (tenant/sub/rg) is required when {@code clusterAuthMode} is anything
 * other than {@code SA_INCLUSTER}.
 */
@Component
public class AzureAgcScopeValidator implements DeploymentScopeValidator {

    private static final String CTX = "AZURE_APP_GW_CONTAINERS";
    private static final Set<String> CLUSTER_AUTH_MODES = Set.of("AZURE", "SA_INCLUSTER");
    private static final Set<String> API_STYLES = Set.of("GATEWAY_API", "INGRESS");

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return Set.of(TargetType.AZURE_APP_GW_CONTAINERS);
    }

    @Override
    public void validate(JsonNode configJson) {
        requireObject(configJson, CTX);

        String clusterAuthMode = requireOneOf(configJson, "clusterAuthMode", CLUSTER_AUTH_MODES, CTX);
        if (!"SA_INCLUSTER".equals(clusterAuthMode)) {
            requireString(configJson, "tenantId", CTX);
            requireString(configJson, "subscriptionId", CTX);
            requireString(configJson, "resourceGroup", CTX);
        } else {
            optionalString(configJson, "tenantId");
        }

        requireString(configJson, "clusterName", CTX);
        requireString(configJson, "agcNamespace", CTX);
        optionalOneOf(configJson, "apiStyle", API_STYLES, CTX);
        requireNonEmptyArray(configJson, "secretNamespaces", CTX);
    }
}
