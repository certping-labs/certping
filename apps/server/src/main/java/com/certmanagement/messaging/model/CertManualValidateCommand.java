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
 * {@code MessageType=CERT_MANUAL_DNS_VALIDATE}.
 *
 * <p>Application properties (for log correlation; routing is by queue):
 * <ul>
 *   <li>{@code organizationId}    — the organization</li>
 *   <li>{@code MessageType} — {@code "CERT_MANUAL_DNS_VALIDATE"}</li>
 *   <li>{@code requestId}   — idempotency key</li>
 * </ul>
 *
 * <p>{@code txtRecords} is populated from {@code cert_manual_issuance_state.txt_records} so the
 * agent can run DNS propagation pre-verification before resuming the ACME order, without an
 * extra ACME API round-trip.
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertManualValidateCommand {

    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String requestId;
    private String correlationId;
    private String certificateXref;

    private String domain;
    private boolean wildcard;
    private boolean san;

    private CaProvider caProvider;
    private String acmeAccountHandle;
    private String acmeOrderUrl;
    private String certSecretHandle;

    private List<SanDomainEntry> sanDomainEntries;

    /**
     * Pre-computed TXT record names and digest values from the stored ACME order state.
     * The agent uses these for DNS pre-verification before resuming the ACME challenge.
     */
    private List<TxtRecord> txtRecords;

    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();

    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SanDomainEntry {
        private List<String> patterns;
    }

    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class TxtRecord {
        /** e.g. {@code _acme-challenge.example.com} */
        private String recordName;
        /** ACME digest value */
        private String recordValue;
        private String domain;
    }
}
