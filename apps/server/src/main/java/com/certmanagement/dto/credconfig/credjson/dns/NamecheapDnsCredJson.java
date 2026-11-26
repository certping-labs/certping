// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Complete Namecheap DNS credential, stored in the agent secret store, for the agent-side XML API client.
 *
 * <p>The agent derives {@code clientIp} from its environment because Namecheap requires that IP
 * to be allowlisted. {@link NamecheapDnsConfigJson} holds the non-secret account metadata; the
 * {@code apiKey} stays in the secret.
 *
 * <p><b>Required fields:</b> {@code apiUser}, {@code username}, {@code apiKey}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class NamecheapDnsCredJson implements CredJsonPayload {
    private String apiUser;
    private String username;
    private String apiKey;
}
