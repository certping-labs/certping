// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AZURE_KV}.
 *
 * <p>One credential = one vault. The vault URI lives here in the scope, not in the per-cert targets.
 *
 * @param authMode            SERVICE_PRINCIPAL | WORKLOAD_IDENTITY
 * @param tenantId            required for both modes (Azure AD tenant)
 * @param clientId            required for WORKLOAD_IDENTITY — the Azure AD app the federated token is exchanged
 *                            for. Without this the SDK would fall back to the pod's default AZURE_CLIENT_ID env
 *                            var, which may belong to the cluster's platform UAMI rather than the deploy SP.
 *                            Ignored for SERVICE_PRINCIPAL (clientId comes from the KV credential blob there).
 * @param federatedTokenFile  optional override for the projected SA token file path. Defaults to the env var
 *                            {@code AZURE_FEDERATED_TOKEN_FILE} injected by the workload-identity webhook.
 * @param vaultUri            required — the single target vault, e.g. {@code https://my-kv.vault.azure.net/}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureKvScope(
        String authMode,
        String tenantId,
        String clientId,
        String federatedTokenFile,
        String vaultUri) {}
