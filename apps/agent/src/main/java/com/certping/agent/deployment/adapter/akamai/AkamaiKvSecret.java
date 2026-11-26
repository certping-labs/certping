// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Akamai KV secret payload — EdgeGrid auth credentials only. Parsed from the
 * {@code deploymentCredHandle} secret content.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AkamaiKvSecret(String clientToken, String accessToken, String clientSecret) {}
