// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.WorkloadIdentityCredentialBuilder;
import com.certping.agent.deployment.adapter.azure.AzureDeploymentAuthHelper;
import com.certping.agent.exception.PermanentAgentException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Single entry point for Azure credential resolution. Closes the Workload-Identity gap
 * that today's {@link AzureDeploymentAuthHelper} has — it only supports SERVICE_PRINCIPAL.
 *
 * <p>Returns the SDK-native {@link TokenCredential}. Callers that also need an
 * {@link AzureProfile} can call {@link #buildProfile} separately.
 */
@Slf4j
@Component
public class AzureCloudCredentialResolver {

    public TokenCredential resolve(AzureAuthMode mode, AzureAuthScope scope, AzureAuthSecret kv, String context) {
        if (mode == null) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential is missing 'authMode'");
        }
        AzureAuthSecret secret = kv != null ? kv : AzureAuthSecret.empty();
        if (scope == null) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential scope is required");
        }

        return switch (mode) {
            case SERVICE_PRINCIPAL -> resolveServicePrincipal(scope, secret, context);
            case WORKLOAD_IDENTITY -> resolveWorkloadIdentity(scope, secret, context);
        };
    }

    public AzureProfile buildProfile(AzureAuthScope scope, String context) {
        AzureDeploymentAuthHelper.requireField("tenantId", scope.tenantId(), context);
        AzureDeploymentAuthHelper.requireUuid("tenantId", scope.tenantId(), context);
        AzureDeploymentAuthHelper.requireField("subscriptionId", scope.subscriptionId(), context);
        AzureDeploymentAuthHelper.requireUuid("subscriptionId", scope.subscriptionId(), context);
        return new AzureProfile(scope.tenantId(), scope.subscriptionId(), AzureEnvironment.AZURE);
    }

    private TokenCredential resolveServicePrincipal(AzureAuthScope scope, AzureAuthSecret kv, String context) {
        AzureDeploymentAuthHelper.requireField("tenantId", scope.tenantId(), context);
        AzureDeploymentAuthHelper.requireUuid("tenantId", scope.tenantId(), context);
        requireClientId(kv.clientId(), context);
        AzureDeploymentAuthHelper.requireUuid("clientId", kv.clientId(), context);
        if (!kv.hasClientSecret()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " SERVICE_PRINCIPAL auth mode requires clientSecret in KV secret");
        }
        log.debug("{}: building SERVICE_PRINCIPAL credential (clientId={})", context, kv.clientId());
        return new ClientSecretCredentialBuilder()
                .clientId(kv.clientId())
                .clientSecret(kv.clientSecret())
                .tenantId(scope.tenantId())
                .build();
    }

    private TokenCredential resolveWorkloadIdentity(AzureAuthScope scope, AzureAuthSecret kv, String context) {
        AzureDeploymentAuthHelper.requireField("tenantId", scope.tenantId(), context);
        AzureDeploymentAuthHelper.requireUuid("tenantId", scope.tenantId(), context);

        // clientId: KV secret wins, scope is the fallback. Lets one credential record be reused
        // across SP and WI modes — operators store {clientId,clientSecret} in KV and only the
        // clientSecret is ignored under WI.
        String clientId = (kv.clientId() != null && !kv.clientId().isBlank())
                ? kv.clientId()
                : scope.clientId();
        requireClientId(clientId, context);
        AzureDeploymentAuthHelper.requireUuid("clientId", clientId, context);

        log.debug("{}: building WORKLOAD_IDENTITY credential (clientId={}, tokenFile={})",
                context, clientId,
                scope.federatedTokenFile() != null ? scope.federatedTokenFile() : "(env)");
        WorkloadIdentityCredentialBuilder builder = new WorkloadIdentityCredentialBuilder()
                .clientId(clientId)
                .tenantId(scope.tenantId());
        if (scope.federatedTokenFile() != null && !scope.federatedTokenFile().isBlank()) {
            builder.tokenFilePath(scope.federatedTokenFile());
        }
        return builder.build();
    }

    // Its own code so the user-facing message can name the field.
    private static void requireClientId(String clientId, String context) {
        if (clientId == null || clientId.isBlank()) {
            throw new PermanentAgentException("DEPLOY_AZURE_CLIENT_ID_MISSING",
                    context + " credential missing required field: clientId");
        }
    }
}
