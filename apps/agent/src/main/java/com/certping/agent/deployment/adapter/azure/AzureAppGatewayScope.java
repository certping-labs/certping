// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AZURE_APP_GW}.
 *
 * <p>One credential = one Application Gateway. The resource group, gateway name,
 * available listeners, and Key Vault URI live in scope. The per-cert SSL cert
 * resource name (and KV cert name) lives in {@link AzureAppGatewayTargets} so one
 * AGW credential can deploy many independent certs (each its own SSL cert resource
 * on the AGW).
 *
 * @param authMode             SERVICE_PRINCIPAL | WORKLOAD_IDENTITY
 * @param tenantId             required for SERVICE_PRINCIPAL
 * @param subscriptionId       required — Azure subscription
 * @param clientId             optional WORKLOAD_IDENTITY hint
 * @param federatedTokenFile   optional WORKLOAD_IDENTITY hint
 * @param resourceGroup        required — the single resource group
 * @param appGateway           required — the single App Gateway name
 * @param listeners            required — all available listener names on this AGW
 * @param keyVaultUri          required — Key Vault URI where the cert is imported
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureAppGatewayScope(
        String authMode,
        String tenantId,
        String subscriptionId,
        String clientId,
        String federatedTokenFile,
        String resourceGroup,
        String appGateway,
        List<String> listeners,
        String keyVaultUri) {}
