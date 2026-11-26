// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Metadata-only agent-to-server audit event: a SCEP enrollment was received, before Intune validation. */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScepCertRequestedMessage {
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
    private String publicKeyAlgorithm;
    private Integer keySize;
    private String requestedAt;
}
