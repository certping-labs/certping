// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.cloudflare;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code targetsJson} for {@code CLOUDFLARE_EDGE}.
 *
 * <p>All configuration lives in the credential scope (one zone per credential).
 * Targets are empty — nothing to select per-cert.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CloudflareTargets() {}
