// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.cloudflare;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code CLOUDFLARE_EDGE}.
 *
 * <p>One credential = one Cloudflare zone. Bundle method and cert type have sensible
 * defaults in the adapter.
 *
 * @param zoneId        required — Cloudflare zone ID
 * @param bundleMethod  optional — ubiquitous (default) | optimal | force
 * @param certType      optional — sni_custom (default) | legacy_custom
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CloudflareScope(
        String zoneId,
        String bundleMethod,
        String certType) {}
