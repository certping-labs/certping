// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Outbound — {@code CERT_MANUAL_TXT_RESPONSE}: DNS-01 TXT records plus ACME order URL and account KV path for the server to persist.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertManualTxtResponse {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private List<TxtRecord> txtRecords;
    private String acmeOrderUrl;
    private String acmeAccountHandle;
    private String respondedAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TxtRecord {
        private String recordName;
        private String recordValue;
        private String domain;
    }
}
