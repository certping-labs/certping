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
import java.util.Map;

/**
 * Published to the organization's inbound queue ({orgId}-agent-inbound) with MessageType=CERT_RENEWAL.
 *
 * Application properties set on the TransportMessage (for log correlation; routing is by queue):
 *   organizationId    — the organization
 *   MessageType — "CERT_RENEWAL"
 *   requestId   — idempotency key
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertRenewalCommand {

    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String requestId;
    private String correlationId;
    private String certificateXref;

    private String domain;
    private Boolean wildcard;

    private CaProvider caProvider;

    /**
     * Validity period the original issuance requested. Honored by paid CAs;
     * ignored by LE (always 90d). Null = use agent default.
     */
    private Integer validityDays;

    /**
     * DNS provider type — used by the agent to select the correct DNS API client.
     * Values: CLOUDFLARE | AWS_ROUTE53 | GODADDY | NAMECHEAP | NAMEDOTCOM | HOSTINGER | CERTPING | AZURE_DNS
     */
    private String dnsProvider;

    /** Secret-store handle where the renewed cert PEM will be stored */
    private String certSecretHandle;

    /**
     * Secret-store handle where the CURRENT (about-to-be-renewed) cert PEM lives.
     * Passed through to the agent so LE ARI can hint {@code newOrder.replaces(previousCert)} —
     * unlocks LE's "5 duplicate certs / week" exemption and lets the CA mark the old cert
     * as superseded server-side. Null on first issuance and on non-LE CAs.
     */
    private String previousCertSecretHandle;

    /** Secret-store handle of the DNS provider credential */
    private String dnsCredentialHandle;

    /** Non-secret DNS provider config, for providers that split secrets from account metadata. */
    private String dnsCredentialConfigJson;

    /** Secret-store handle of the ACME account key (Let's Encrypt only) */
    private String acmeAccountHandle;

    /** Secret-store handle of the CA credential (DigiCert only) */
    private String caCredentialHandle;

    /** SAN domain entries for multi-provider SAN certs (mirrors issuance entries) */
    private List<SanDomainEntry> sanDomainEntries;

    /** ISO-8601 expiry of the current cert — informational, aids agent logging */
    private String currentValidTo;

    /** Previous DigiCert order id used as renewal_of_order_id by the agent. */
    private String orderId;

    /** Days before expiry that renewals start; the agent replaces only with twice this left on the order's term. */
    private Integer renewalWindowDays;

    /** Optional CA-specific options forwarded from the original issuance request. */
    private Map<String, String> caOptions;

    /** ISO-8601 UTC timestamp when the server dispatched this command — matches agent model field */
    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();

    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SanDomainEntry {
        /** DNS provider type for this SAN group. Values: CLOUDFLARE | AWS_ROUTE53 | GODADDY | NAMECHEAP | NAMEDOTCOM | HOSTINGER | CERTPING | AZURE_DNS */
        private String dnsProvider;
        private String dnsCredentialHandle;
        private String dnsCredentialConfigJson;
        private List<String> patterns;
    }
}
