// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.gcp;

import com.fasterxml.jackson.annotation.JsonAlias;

/**
 * GCP KV secret payload. Either form is accepted; both are nullable for {@code WORKLOAD_IDENTITY}.
 */
public record GcpAuthSecret(
        @JsonAlias({"serviceAccountKeyJson"}) String serviceAccountJson,
        @JsonAlias({"serviceAccountKeyJsonBase64"}) String serviceAccountJsonBase64) {

    public static GcpAuthSecret empty() {
        return new GcpAuthSecret(null, null);
    }

    public boolean hasKey() {
        return (serviceAccountJson != null && !serviceAccountJson.isBlank())
                || (serviceAccountJsonBase64 != null && !serviceAccountJsonBase64.isBlank());
    }
}
