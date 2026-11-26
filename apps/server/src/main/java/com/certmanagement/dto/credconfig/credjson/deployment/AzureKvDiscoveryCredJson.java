// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

/**
 * Azure Key Vault import (deploy cert into customer KV) + KV discovery scope.
 *
 * <p><b>Required:</b> {@code tenantId}, and one of {@code vaultUri} OR a non-empty {@code allowedVaults}
 * (agent uses {@code allowedVaults[0]} when {@code vaultUri} is absent).
 *
 * <p><b>Conditional:</b> {@code clientId} and {@code clientSecret} REQUIRED together for
 * SERVICE_PRINCIPAL auth; OPTIONAL for WORKLOAD_IDENTITY (agent uses the federated token).
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AzureKvDiscoveryCredJson implements CredJsonPayload {
    private String tenantId;
    private String clientId;
    private String clientSecret;
    private String vaultUri;
    private List<String> allowedVaults;
}
