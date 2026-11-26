// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AZURE_AFD}.
 *
 * <p>One credential = one AFD profile. The Key Vault URI and available custom domains live
 * in scope. The per-cert KV cert name and AFD Secret resource name are carried in
 * {@link AzureAfdTargets} so one AFD profile can host many independent certs (each its own
 * Secret resource on the profile).
 *
 * <p>{@code keyVaultResourceGroup} and {@code keyVaultSubscriptionId} are optional — only set
 * them when the Key Vault lives in a different resource group or subscription than the AFD
 * profile. AFD's {@code secretSource.id} requires the ARM resource ID of the KV secret, so we
 * need the KV's RG (and sub) to construct it; we default both to the AFD's RG / subscription
 * if the operator doesn't specify.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureAfdScope(
        String authMode,
        String tenantId,
        String subscriptionId,
        String clientId,
        String federatedTokenFile,
        String resourceGroup,
        String profileName,
        String keyVaultUri,
        String keyVaultResourceGroup,
        String keyVaultSubscriptionId,
        List<String> customDomains) {}
