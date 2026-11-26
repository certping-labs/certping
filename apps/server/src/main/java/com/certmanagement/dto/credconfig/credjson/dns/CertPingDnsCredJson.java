// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * CertPing DNS credential for the CertPing DNS API (a DNS provider for ACME DNS-01), stored as
 * {@code {"apiKey":"cpk_live_…"}}; the key needs dns:acme or dns:edit. Mirrors the agent's
 * {@code CertPingDnsProvider}, which picks the API host itself. Older payloads may still carry
 * an {@code apiUrl}; it is ignored.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertPingDnsCredJson implements CredJsonPayload {
    private String apiKey;
}
