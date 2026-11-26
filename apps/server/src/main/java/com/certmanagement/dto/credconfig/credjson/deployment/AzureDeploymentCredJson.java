// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Azure deployment (App Gateway / AFD / App Gateway for Containers).
 *
 * <p><b>Conditional on {@code configJson.authMode}:</b>
 * <ul>
 *   <li>{@code SERVICE_PRINCIPAL} — both {@code clientId} and {@code clientSecret} REQUIRED.</li>
 *   <li>{@code WORKLOAD_IDENTITY} — both OPTIONAL; agent uses the federated token.</li>
 * </ul>
 * <p>Tenant/subscription/etc. live in {@code configJson}, not here.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AzureDeploymentCredJson implements CredJsonPayload {
    private String clientId;
    private String clientSecret;
}
