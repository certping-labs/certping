// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.certmanagement.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Inbound response — agent → server. MessageType = {@code CERT_REVOCATION_RESPONSE}.
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertRevocationResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private CaProvider caProvider;
    private String revocationReason;
    /** ISO-8601 UTC from agent at CA confirmation */
    private String revokedAt;
}
