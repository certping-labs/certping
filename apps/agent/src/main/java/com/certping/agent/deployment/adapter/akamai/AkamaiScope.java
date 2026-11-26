// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Parsed shape of {@code credentialScopeJson} for {@code AKAMAI_CPS}.
 *
 * <p>One credential = one Akamai CPS enrollment. Polling tunables have sensible defaults
 * in the adapter so operators only need to provide {@code host} and {@code enrollmentId}.
 *
 * @param host                  required — EdgeGrid API base host
 * @param enrollmentId          required — single CPS enrollment ID
 * @param pollIntervalSeconds   optional — defaults to 300
 * @param pollTimeoutMinutes    optional — defaults to 480
 * @param waitForStatus         optional — defaults to "complete"
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AkamaiScope(
        String host,
        String enrollmentId,
        Integer pollIntervalSeconds,
        Integer pollTimeoutMinutes,
        String waitForStatus) {}
