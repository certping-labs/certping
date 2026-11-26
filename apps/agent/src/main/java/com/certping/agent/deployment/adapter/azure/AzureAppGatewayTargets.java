// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * {@code targetsJson} for {@code AZURE_APP_GW}.
 *
 * @param sslCertName    required first deploy — the SSL cert resource name on the AGW
 *                       (and the KV cert name). Each cert lifecycle on this AGW gets its
 *                       own SSL cert resource. Targets-first precedence: changes here
 *                       trigger a rename — agent creates a new SSL cert resource on the
 *                       AGW and repoints listeners. The old SSL cert resource becomes
 *                       orphan on the gateway (operator cleans up manually).
 * @param listenerNames  selected listener names — must be a subset of {@code scope.listeners}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AzureAppGatewayTargets(String sslCertName, List<String> listenerNames) {}
