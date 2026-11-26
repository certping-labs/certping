// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent;

/**
 * Which cloud backs the agent-facing secret store today.
 *
 * <p>Matches the agent-side enum shape ({@code com.certping.agent.secrets.SecretStoreProvider}) so
 * handles produced by the server parse cleanly on the agent.
 */
public enum AgentSecretStoreProvider {
    AZURE_KV,
    AWS_SECRETS_MANAGER,
    GCP_SECRET_MANAGER,
    LOCAL
}
