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
 * Published to the organization's inbound queue ({orgId}-agent-inbound) with MessageType=CERT_ISSUANCE.
 *
 * Application properties set on the TransportMessage (for log correlation; routing is by queue):
 *   organizationId    — the organization
 *   MessageType — "CERT_ISSUANCE"
 *   requestId   — idempotency key
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertIssuanceCommand {

    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String requestId;
    private String correlationId;
    private String certificateXref;

    private String domain;
    private Boolean wildcard;
    private Boolean san;

    private CaProvider caProvider;

    /**
     * Requested validity in days. Honored by DigiCert / GlobalSign. Ignored
     * for LE (always 90d). Null = use agent default (90d).
     */
    private Integer validityDays;

    /**
     * DNS provider type — used by the agent to select the correct DNS API client.
     * Values: CLOUDFLARE | AWS_ROUTE53 | GODADDY | NAMECHEAP | NAMEDOTCOM | HOSTINGER | CERTPING | AZURE_DNS
     */
    private String dnsProvider;

    /** Secret-store handle of the DNS provider credential */
    private String dnsCredentialHandle;

    /** Non-secret DNS provider config, for providers that split secrets from account metadata. */
    private String dnsCredentialConfigJson;

    /** Secret-store handle of the ACME account key (Let's Encrypt only) */
    private String acmeAccountHandle;

    /** Secret-store handle of the CA credential (DigiCert only) */
    private String caCredentialHandle;

    /** SAN domain entries for multi-provider SAN certs */
    private List<SanDomainEntry> sanDomainEntries;

    /** Optional CA-specific options forwarded from the issuance request. */
    private Map<String, String> caOptions;

    /**
     * Non-null when the cert being issued is a CDN-special cert.
     * Currently only "AKAMAI_CPS" is supported — signals the agent to obtain the CSR
     * from Akamai CPS instead of generating one locally.
     */
    private String specialCertType;

    /**
     * KV path for the deployment credential used to communicate with the special CDN.
     * Required when specialCertType is set. For AKAMAI_CPS this points to the
     * AkamaiCpsDeploymentCredential JSON secret in the agent's secret store.
     */
    private String specialDeploymentCredHandle;

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
