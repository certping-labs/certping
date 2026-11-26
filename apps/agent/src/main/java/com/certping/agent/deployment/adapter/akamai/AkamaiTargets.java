// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code targetsJson} for {@code AKAMAI_CPS}.
 *
 * <p>All configuration lives in the credential scope (one enrollment per credential).
 * Targets are empty — nothing to select per-cert.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AkamaiTargets() {}
