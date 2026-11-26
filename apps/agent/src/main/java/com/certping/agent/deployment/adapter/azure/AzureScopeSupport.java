// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.certping.agent.deployment.cloud.azure.AzureAuthMode;
import com.certping.agent.deployment.cloud.azure.AzureAuthScope;
import com.certping.agent.deployment.cloud.azure.AzureAuthSecret;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.AzureDeploymentCredential;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared parsing helpers used by all Azure adapters to convert wire JSON into the
 * cloud-resolver's typed inputs.
 */
public final class AzureScopeSupport {

    private AzureScopeSupport() {}

    public static AzureAuthMode parseAuthMode(String authMode, String context) {
        if (authMode == null || authMode.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credentialScopeJson missing 'authMode'");
        }
        try {
            return AzureAuthMode.valueOf(authMode.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " unknown Azure authMode: '" + authMode + "'");
        }
    }

    public static AzureAuthScope toAuthScope(
            String tenantId, String subscriptionId, String clientId, String federatedTokenFile) {
        return new AzureAuthScope(tenantId, subscriptionId, clientId, federatedTokenFile);
    }

    public static AzureAuthSecret parseKvSecret(ObjectMapper objectMapper, String credRaw, String context) {
        if (credRaw == null || credRaw.isBlank()) {
            return AzureAuthSecret.empty();
        }
        try {
            AzureDeploymentCredential parsed = objectMapper.readValue(credRaw, AzureDeploymentCredential.class);
            return new AzureAuthSecret(parsed.getClientId(), parsed.getClientSecret());
        } catch (Exception ex) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + context + " KV secret JSON: " + ex.getMessage(), ex);
        }
    }
}
