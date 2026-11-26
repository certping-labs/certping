// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Hostinger DNS API credentials — stored as {@code {"apiToken":"..."}} JSON, consistent with the
 * other token-based DNS providers (e.g. Cloudflare).
 *
 * <p><b>Required:</b> {@code apiToken}. Agent rejects null/blank with {@code DNS_CREDENTIAL_INVALID}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class HostingerDnsCredJson implements CredJsonPayload {
    private String apiToken;
}
