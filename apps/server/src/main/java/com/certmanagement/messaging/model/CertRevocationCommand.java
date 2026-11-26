// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.certmanagement.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

/**
 * Outbound command — server → agent. MessageType = {@code CERT_REVOCATION_COMMAND}.
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertRevocationCommand {
    private String requestId;
    private String correlationId;
    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String certificateXref;
    private String domain;
    private CaProvider caProvider;
    private String certSecretHandle;
    private String orderId;
    /** The certificate's serial (hex). */
    private String serialNumber;
    /** Secret-store handle of the CA credential (required for DIGICERT). */
    private String caCredentialHandle;
    private String revocationReason;
    private String requestedAt;
    private Integer userId;
}
