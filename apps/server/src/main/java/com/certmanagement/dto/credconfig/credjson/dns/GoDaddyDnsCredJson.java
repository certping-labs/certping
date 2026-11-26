// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * GoDaddy DNS API credentials.
 *
 * <p><b>Required fields (both):</b> {@code apiKey}, {@code apiSecret}.
 * Agent rejects either being null/blank with {@code DNS_CREDENTIAL_INVALID}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class GoDaddyDnsCredJson implements CredJsonPayload {
    private String apiKey;
    private String apiSecret;
}
