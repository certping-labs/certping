// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Metadata-only agent-to-server terminal event for a non-issued SCEP enrollment: REJECTED or FAILED. */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScepCertResultMessage {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    /** Device-source route that served the request (version 2). Version 1 carried it as endpointId. */
    private String connectionProfileRef;
    private String endpointId;
    /** Optional certificate-profile hint — never a routing key. */
    private String profileXref;
    private String intuneTransactionId;
    private String csrFingerprintSha256;
    private String status;
    private String stage;
    private boolean retryable;
    private String errorCode;
    private String errorMessage;
    private String occurredAt;
}
