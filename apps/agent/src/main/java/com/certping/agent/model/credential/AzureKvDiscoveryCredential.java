// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

/**
 * Credential for Azure Key Vault discovery.
 *
 * <p>Supports two authentication modes:
 * <ul>
 *   <li><b>Service principal</b> — provide {@code clientId} and {@code clientSecret}.
 *       The SP must have at minimum the {@code Key Vault Certificate Reader} role.</li>
 *   <li><b>Workload identity</b> — omit {@code clientId} and {@code clientSecret}.
 *       The agent's managed/workload identity is used instead (e.g. when the target vault
 *       is the same vault the agent already has access to).</li>
 * </ul>
 *
 * <p>The target vault is resolved from {@code vaultUri} if present, otherwise from the
 * first entry in {@code allowedVaults} (backward-compatible with deployment credentials).
 *
 * <p>Minimal JSON for workload-identity mode:
 * <pre>
 * {
 *   "tenantId":     "...",
 *   "allowedVaults": ["https://my-keyvault.vault.azure.net/"]
 * }
 * </pre>
 *
 * <p>Full JSON for service-principal mode:
 * <pre>
 * {
 *   "tenantId":     "...",
 *   "clientId":     "...",
 *   "clientSecret": "...",
 *   "vaultUri":     "https://my-keyvault.vault.azure.net/"
 * }
 * </pre>
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AzureKvDiscoveryCredential {
    private String       tenantId;
    private String       clientId;
    private String       clientSecret;
    private String       vaultUri;
    private List<String> allowedVaults;

    /**
     * Returns the effective vault URI to target for discovery.
     * Uses {@code vaultUri} if set, otherwise falls back to the first entry in
     * {@code allowedVaults} (present in deployment-style credentials).
     */
    public String getEffectiveVaultUri() {
        if (vaultUri != null && !vaultUri.isBlank()) return vaultUri;
        if (allowedVaults != null && !allowedVaults.isEmpty()) return allowedVaults.get(0);
        return null;
    }

    public boolean hasServicePrincipalCredentials() {
        return clientId     != null && !clientId.isBlank()
            && clientSecret != null && !clientSecret.isBlank();
    }
}
