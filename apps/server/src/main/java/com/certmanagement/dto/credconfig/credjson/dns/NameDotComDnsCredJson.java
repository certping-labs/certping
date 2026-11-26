// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Name.com DNS API credentials.
 *
 * <p><b>Required fields (both):</b> {@code username}, {@code apiToken}.
 * Agent rejects either being null/blank with {@code DNS_CREDENTIAL_INVALID}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class NameDotComDnsCredJson implements CredJsonPayload {
    private String username;
    private String apiToken;
}
