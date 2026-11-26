// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * F5 BIG-IP KV secret payload — sensitive auth only.
 *
 * <p>All non-sensitive config (host, port, partition allow-list, deviceGroup, verifySsl)
 * lives in {@code credentialScopeJson}; per-cert deployment plan
 * (partitions × clientSslProfiles) lives in {@code targetsJson}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class F5BigIpDeploymentCredential {
    /** BIG-IP iControl REST username (e.g. certping-api). */
    private String username;

    /** BIG-IP iControl REST password. */
    private String password;
}
