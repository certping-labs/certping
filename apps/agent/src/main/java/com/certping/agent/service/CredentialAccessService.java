// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.service;

import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Read-only accessor for credentials kept in the agent's secret store.
 *
 * Credential values never travel over the gateway. The server stores only a secret-store
 * handle (credential_references table) and embeds it in command messages.
 *
 * At issuance / renewal time, this service reads the raw credential value from the secret
 * store, using the handle embedded in the incoming message.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialAccessService {

    private final SecretStore secretStore;

    /**
     * Reads a raw credential value from the secret store.
     *
     * The handle comes from the server inside the command message
     * (e.g. dnsCredentialHandle, deploymentCredHandle fields), in the format of the configured
     * secret store (for example an Azure Key Vault secret URI).
     *
     * @param kvSecretUri  secret-store handle as embedded in the command message
     * @return             raw secret value — API token, PEM string, or JSON for multi-field credentials
     * @throws com.certping.agent.exception.PermanentAgentException  if secret not found, access denied,
     *                                                                 or URI is malformed
     * @throws com.certping.agent.exception.TransientAgentException  if network or transient HTTP error
     */
    public String readSecret(String kvSecretUri) {
        log.debug("Reading credential from the secret store: {}", kvSecretUri);
        return secretStore.read(kvSecretUri);
    }
}
