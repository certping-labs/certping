// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Inbound — {@code CERT_MANUAL_TXT_REQUEST}: the server asks the agent for DNS-01 TXT values and ACME order state
 * for manual Let's Encrypt issuance (before the user publishes TXT in DNS).
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertManualTxtRequestMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String domain;
    private boolean wildcard;
    private boolean san;
    private CaProvider caProvider;
    /** Null on first issuance; KV URI of existing ACME account key on retry. */
    private String acmeAccountHandle;
    private List<SanDomainEntry> sanDomainEntries;
    private String requestedAt;
}
