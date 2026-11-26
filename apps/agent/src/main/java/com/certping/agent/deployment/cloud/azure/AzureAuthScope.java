// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.azure;

/**
 * Azure credential scope — fields parsed from {@code credentialScopeJson} on the wire.
 *
 * @param tenantId          required
 * @param subscriptionId    required for ARM-targeting adapters; nullable for KV-only flows
 * @param clientId          required for WORKLOAD_IDENTITY (federated identity client)
 * @param federatedTokenFile path to federated token file; null = use AZURE_FEDERATED_TOKEN_FILE env var
 */
public record AzureAuthScope(
        String tenantId,
        String subscriptionId,
        String clientId,
        String federatedTokenFile) {}
