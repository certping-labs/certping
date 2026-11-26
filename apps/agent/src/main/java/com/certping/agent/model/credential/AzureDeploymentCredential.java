// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Azure KV secret payload — sensitive auth only.
 *
 * <p>Both fields nullable for {@code WORKLOAD_IDENTITY} mode (federated token from environment).
 * For {@code SERVICE_PRINCIPAL} both are required.
 *
 * <p>All non-sensitive Azure config (tenantId, subscriptionId, allowed-* lists, vaultUri,
 * resourceGroup, profileName, etc.) lives in {@code credentialScopeJson};
 * per-cert deployment plan (vaults, listeners, customDomains) lives in {@code targetsJson}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AzureDeploymentCredential {
    private String clientId;
    private String clientSecret;
}
