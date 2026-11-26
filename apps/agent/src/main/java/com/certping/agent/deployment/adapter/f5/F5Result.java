// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Parsed shape of the {@code result} slice for {@code F5_BIGIP}:
 * <pre>
 * {
 *   "certName": "cert-0001_v2",
 *   "keyName": "cert-0001_v2",
 *   "version": 2,
 *   "profilesPatched": ["clientssl-api", "clientssl-www"],
 *   "lastSyncedAt": "ISO-8601"
 * }
 * </pre>
 *
 * <p>{@code version} drives deterministic name versioning. On subsequent deploys the adapter
 * computes {@code v(N+1)} where N is the prior version.
 *
 * <p>{@code profilesPatched} captures which profiles were actually patched in the previous
 * rotation — used as the seed set for the next rotation's discovery.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record F5Result(
        String certName,
        String keyName,
        Integer version,
        List<String> profilesPatched,
        String lastSyncedAt) {

    public static F5Result empty() {
        return new F5Result(null, null, null, List.of(), null);
    }
}
