// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.time.Instant;

/**
 * The non-secret details of a CertPing DNS key, kept in its credential's {@code config}: which CertPing DNS API
 * token it is and when it stops working, so its admins are warned and its renewals held before then.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertPingDnsKeyConfig implements CredJsonPayload {
    private Long tokenId;
    /** {@code cpk_live_} and the first characters of the key, as the CertPing DNS portal shows it. */
    private String tokenPrefix;
    /** Stored as an ISO-8601 string whatever the mapper's defaults. */
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private Instant expiresAt;
}
