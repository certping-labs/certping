// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.cloudflare;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of the {@code result} slice for {@code CLOUDFLARE_EDGE}:
 * {@code { "certId": "..." }}.
 *
 * <p>Null/empty on first deploy. On subsequent deploys, the adapter uses the prior
 * cert id to {@code PATCH} (atomic in-place rotation) instead of {@code POST}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CloudflareResult(String certId) {

    public static CloudflareResult empty() {
        return new CloudflareResult(null);
    }
}
