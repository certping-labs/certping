// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Mirrors the agent-side JSON shape Route53 reads for static IAM creds.
 *
 * <p><b>Required fields (both):</b>
 * <ul>
 *   <li>{@code accessKeyId}</li>
 *   <li>{@code secretAccessKey}</li>
 * </ul>
 * <p>The agent's {@code DnsProviderFactory} rejects either being null/blank with {@code DNS_CREDENTIAL_INVALID}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AwsRoute53DnsCredJson implements CredJsonPayload {
    private String accessKeyId;
    private String secretAccessKey;
}
