// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AZURE_APP_GW_CONTAINERS}.
 *
 * <p>One credential = one AGC cluster + namespace. The cluster name, AGC namespace, and
 * allowed secret namespaces all live in scope.
 *
 * @param tenantId            required for ARM auth (non-SA_INCLUSTER)
 * @param subscriptionId      required for ARM auth
 * @param clientId            optional — picks a specific managed identity when WORKLOAD_IDENTITY
 * @param federatedTokenFile  optional — overrides the default federated token file path
 * @param resourceGroup       required for ARM auth
 * @param clusterAuthMode     AZURE | SA_INCLUSTER
 * @param clusterName         required — AKS cluster name
 * @param agcNamespace        required — namespace where AGC's controller lives
 * @param apiStyle            optional — GATEWAY_API (default) | INGRESS
 * @param secretNamespaces    required — allow-list of K8s namespaces TLS secrets may land in
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureAgcScope(
        String tenantId,
        String subscriptionId,
        String clientId,
        String federatedTokenFile,
        String resourceGroup,
        String clusterAuthMode,
        String clusterName,
        String agcNamespace,
        String apiStyle,
        List<String> secretNamespaces) {}
