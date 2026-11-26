// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.telemetry;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Everything an opt-in usage report contains. No hostnames, URLs, domain names, email addresses,
 * names, tokens or certificates: an installation id minted at first start, versions, and counts.
 * {@code docs/self-hosting.md#privacy-and-telemetry} lists these fields; adding one is a documentation change too.
 *
 * @param schema         {@code certping.telemetry.v1}
 * @param installationId random UUID from the {@code installation} table
 * @param reportedAt     when the report was built
 * @param version        the server's version, or {@code unknown} outside a release build
 * @param edition        {@code open}
 * @param runtime        Java version, operating system name and architecture, database product and version
 * @param counts         organizations, users, users with two-factor authentication, certificates,
 *                       discovered certificates, deployment targets
 */
public record TelemetryReport(String schema,
                              String installationId,
                              OffsetDateTime reportedAt,
                              String version,
                              String edition,
                              Map<String, String> runtime,
                              Map<String, Long> counts) {

    public static final String SCHEMA = "certping.telemetry.v1";
}
