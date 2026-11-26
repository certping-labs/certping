// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

/**
 * Cloudflare DNS API token — stored as {@code {"apiToken":"..."}} JSON, consistent with the other DNS providers.
 *
 * <p><b>Required:</b> {@code apiToken}. Agent rejects null/blank with {@code DNS_CREDENTIAL_INVALID}.
 * <b>Optional:</b> {@code zoneId}, for a token without Zone Read: the agent then skips the zone lookup.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CloudflareDnsCredJson implements CredJsonPayload {
    private String apiToken;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String zoneId;
}
