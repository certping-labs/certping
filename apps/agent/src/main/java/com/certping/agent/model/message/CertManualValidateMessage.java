// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Inbound — {@code CERT_MANUAL_DNS_VALIDATE}: user has published TXT in DNS; agent verifies propagation,
 * completes ACME DNS-01, finalizes the order, and stores the issued cert in Key Vault.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertManualValidateMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String domain;
    private boolean wildcard;
    private boolean san;
    private CaProvider caProvider;
    private String acmeAccountHandle;
    private String acmeOrderUrl;
    private List<SanDomainEntry> sanDomainEntries;
    private List<TxtRecordEntry> txtRecords;
    private String requestedAt;

    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TxtRecordEntry {
        private String recordName;
        private String recordValue;
    }
}
