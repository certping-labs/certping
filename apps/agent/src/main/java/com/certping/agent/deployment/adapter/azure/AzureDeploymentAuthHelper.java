// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;

import java.util.UUID;

public final class AzureDeploymentAuthHelper {

    public record AzureAuthContext(TokenCredential credential, AzureProfile profile) {}

    private AzureDeploymentAuthHelper() {}

    public static <T> T parseCredential(ObjectMapper objectMapper, String raw, Class<T> type, String context) {
        try {
            return objectMapper.readValue(raw, type);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + context + " credential JSON: " + e.getMessage(), e);
        }
    }

    public static void requireField(String name, String value, String context) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential missing required field: " + name);
        }
    }

    public static void requireUuid(String name, String value, String context) {
        try {
            UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential field '" + name + "' must be a valid UUID, got: '" + value + "'");
        }
    }

    public static TokenCredential buildClientSecretCredential(String tenantId,
                                                              String clientId,
                                                              String clientSecret) {
        return new ClientSecretCredentialBuilder()
                .clientId(clientId)
                .clientSecret(clientSecret)
                .tenantId(tenantId)
                .build();
    }

    public static TokenCredential buildClientSecretCredentialValidated(String tenantId,
                                                                       String clientId,
                                                                       String clientSecret,
                                                                       String context) {
        validateClientCredentials(tenantId, clientId, clientSecret, context);
        return buildClientSecretCredential(tenantId, clientId, clientSecret);
    }

    public static AzureProfile buildProfile(String tenantId, String subscriptionId) {
        return new AzureProfile(tenantId, subscriptionId, AzureEnvironment.AZURE);
    }

    public static AzureProfile buildProfileValidated(String tenantId, String subscriptionId, String context) {
        requireField("subscriptionId", subscriptionId, context);
        requireUuid("subscriptionId", subscriptionId, context);
        return buildProfile(tenantId, subscriptionId);
    }

    public static AzureAuthContext buildAuthContext(String tenantId,
                                                    String clientId,
                                                    String clientSecret,
                                                    String subscriptionId,
                                                    String context) {
        TokenCredential credential = buildClientSecretCredentialValidated(tenantId, clientId, clientSecret, context);
        AzureProfile profile = buildProfileValidated(tenantId, subscriptionId, context);
        return new AzureAuthContext(credential, profile);
    }

    public static void validateClientCredentials(String tenantId,
                                                 String clientId,
                                                 String clientSecret,
                                                 String context) {
        requireField("tenantId", tenantId, context);
        requireField("clientId", clientId, context);
        requireField("clientSecret", clientSecret, context);
        requireUuid("tenantId", tenantId, context);
        requireUuid("clientId", clientId, context);
    }
}
