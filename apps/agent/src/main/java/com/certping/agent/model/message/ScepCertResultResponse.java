// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

/**
 * Terminal non-issued outcome of a SCEP enrollment: {@code REJECTED} (Intune declined the challenge)
 * or {@code FAILED} (the CA refused after validation succeeded). Metadata only — no CSR, challenge,
 * or key material. The successful outcome travels as {@link ScepCertIssuedResponse} instead.
 */
@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScepCertResultResponse {
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
    /** {@code REJECTED} or {@code FAILED}. */
    private String status;
    /** {@code INTUNE_VALIDATION} or {@code CA_SIGNING}. */
    private String stage;
    private boolean retryable;
    private String errorCode;
    private String errorMessage;
    private String occurredAt;
}
