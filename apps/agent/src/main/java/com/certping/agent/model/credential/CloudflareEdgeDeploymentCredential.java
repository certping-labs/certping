// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Cloudflare KV secret payload — sensitive auth only.
 *
 * <p>All non-sensitive Cloudflare config (account, allowed zones, defaults) lives in
 * {@code credentialScopeJson}; per-cert deployment plan (zones to deploy to) lives in
 * {@code targetsJson}; per-cert state (current cert IDs by zone) lives in {@code configJson}
 * (the {@code result} slice of the envelope).
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CloudflareEdgeDeploymentCredential {
    /** Cloudflare API token with SSL/Edit + Zone/Read scopes for the allowed zones. */
    private String apiToken;
}
