// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

/**
 * Audit telemetry: a SCEP enrollment was received and parsed, published before Intune validation.
 * Never authorizes signing. Metadata only — no CSR, challenge, or requested subject/SAN. Correlates
 * to the terminal {@link ScepCertIssuedResponse} or {@link ScepCertResultResponse} by
 * {@code intuneTransactionId} + {@code csrFingerprintSha256}.
 */
@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScepCertRequestedResponse {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    /** The device-source connection that served the request (version 2+). */
    private String connectionProfileRef;
    private String endpointId;
    /** Optional certificate-profile hint; never derived from the endpoint id. */
    private String profileXref;
    private String intuneTransactionId;
    private String csrFingerprintSha256;
    private String publicKeyAlgorithm;
    private Integer keySize;
    private String requestedAt;
}
