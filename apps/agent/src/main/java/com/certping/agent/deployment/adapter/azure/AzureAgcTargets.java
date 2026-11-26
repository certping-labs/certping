// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * {@code targetsJson} for {@code AZURE_APP_GW_CONTAINERS}: selects which
 * namespace/secretName pairs to deploy TLS secrets to.
 * Each {@code namespace} must be in {@code scope.secretNamespaces}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureAgcTargets(List<SecretRef> secrets) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SecretRef(String namespace, String secretName) {}
}
