// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.azure;

/** Azure KV secret payload. Both fields nullable for {@code WORKLOAD_IDENTITY} (no KV secret). */
public record AzureAuthSecret(String clientId, String clientSecret) {

    public static AzureAuthSecret empty() {
        return new AzureAuthSecret(null, null);
    }

    public boolean hasClientSecret() {
        return clientSecret != null && !clientSecret.isBlank();
    }
}
