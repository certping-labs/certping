// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.certmanagement.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

/**
 * Published to the organization's inbound queue ({@code {orgId}-agent-inbound}) with
 * {@code MessageType=CERT_MANUAL_TXT_REQUEST}.
 *
 * <p>Application properties (for log correlation; routing is by queue):
 * <ul>
 *   <li>{@code organizationId}    — the organization</li>
 *   <li>{@code MessageType} — {@code "CERT_MANUAL_TXT_REQUEST"}</li>
 *   <li>{@code requestId}   — idempotency key</li>
 * </ul>
 *
 * <p>The agent creates (or reuses) an ACME account, initiates the DNS-01 order, and returns
 * the required TXT records in a {@code CERT_MANUAL_TXT_RESPONSE} message.
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertManualTxtRequestCommand {

    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String requestId;
    private String correlationId;
    private String certificateXref;

    private String domain;
    private boolean wildcard;
    private boolean san;

    /** Always {@code LETS_ENCRYPT} for the manual flow. */
    private CaProvider caProvider;

    /**
     * KV path to the ACME account key.
     * Null on first issuance. Non-null on retry (reuses the existing account).
     */
    private String acmeAccountHandle;

    /** Secret-store handle where the cert bundle will be stored after issuance. */
    private String certSecretHandle;

    /** SAN patterns — no {@code dnsCredentialHandle} (manual flow: user owns the DNS zone). */
    private List<SanDomainEntry> sanDomainEntries;

    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();

    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SanDomainEntry {
        private List<String> patterns;
    }
}
