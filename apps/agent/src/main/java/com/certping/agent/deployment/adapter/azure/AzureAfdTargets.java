// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * {@code targetsJson} for {@code AZURE_AFD}.
 *
 * @param certificateName  required first deploy — the KV cert name where the cert is imported.
 *                         Each cert lifecycle on this AFD profile gets its own KV cert name.
 *                         Targets-first precedence: changes here trigger a rename — new KV cert
 *                         under the new name; old keeps existing in the vault.
 * @param secretName       required first deploy — the AFD {@code Secret} resource name on the
 *                         profile that wraps the KV cert. Each cert lifecycle gets its own Secret.
 *                         Targets-first precedence: changes here trigger a rename — agent
 *                         creates a new AFD Secret and repoints custom-domain TLS bindings to
 *                         it. The old Secret resource becomes orphan on the profile (operator
 *                         cleans up manually).
 * @param domainNames      selected custom domain names — must be a subset of {@code scope.customDomains}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureAfdTargets(
        String certificateName,
        String secretName,
        List<String> domainNames) {}
