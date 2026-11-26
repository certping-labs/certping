// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret;

import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Integration secrets in the secret store this installation is configured with
 * ({@code certping.agent-secret-store.provider}): encrypted files in the LOCAL directory on a
 * single-server install, or AWS Secrets Manager, Azure Key Vault or GCP Secret Manager. Only the
 * server reads them, so no agent needs access.
 */
@Component
class ConfiguredSecretStore implements SecretStore {

    private final ObjectProvider<AgentSecretStore> stores;

    ConfiguredSecretStore(ObjectProvider<AgentSecretStore> stores) {
        this.stores = stores;
    }

    @Override
    public String writeSecret(String existingRef, String name, String value) {
        AgentSecretStore store = store();
        if (StringUtils.hasText(existingRef) && store.isOwnedByThisCertManager(existingRef)) {
            try {
                return store.update(existingRef, value);
            } catch (ResourceNotFoundException deleted) {
                // Deleted outside CertPing: write it again under its name.
            }
        }
        return store.create(name, value);
    }

    @Override
    public String readSecret(String ref) {
        return store().read(ref);
    }

    private AgentSecretStore store() {
        AgentSecretStore store = stores.getIfAvailable();
        if (store == null || !store.isReady()) {
            throw new IllegalStateException("No secret store is configured for integration secrets: set "
                    + "certping.agent-secret-store.provider (CERTPING_AGENT_SECRET_STORE_PROVIDER) and its settings");
        }
        return store;
    }
}
