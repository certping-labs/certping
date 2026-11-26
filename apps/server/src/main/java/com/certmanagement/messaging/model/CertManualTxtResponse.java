// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Received from the agent on {@code cert-agent-outbound} with
 * {@code MessageType=CERT_MANUAL_TXT_RESPONSE}.
 *
 * <p>The server stores {@code acmeOrderUrl} and {@code acmeAccountHandle} in
 * {@code cert_manual_issuance_state} and sets the certificate status to
 * {@code AWAITING_DNS}. The {@code txtRecords} list is shown to the user so they know
 * which DNS TXT records to add.
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertManualTxtResponse {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;

    private List<TxtRecord> txtRecords;

    /** ACME order URL — stored in {@code cert_manual_issuance_state} and re-sent on DNS validate. */
    private String acmeOrderUrl;

    /** KV path to the ACME account key — also persisted on {@code CertificateEntity}. */
    private String acmeAccountHandle;

    private String respondedAt;

    @Data
    @NoArgsConstructor
    public static class TxtRecord {
        /** e.g. {@code _acme-challenge.example.com} */
        private String recordName;
        /** ACME digest value */
        private String recordValue;
        private String domain;
    }
}
