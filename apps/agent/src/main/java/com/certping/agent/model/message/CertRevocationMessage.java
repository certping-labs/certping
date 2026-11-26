// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Inbound command — Server → Agent.
 * MessageType = "CERT_REVOCATION_COMMAND"
 *
 * <p>The agent reads the cert bundle from {@code certSecretHandle}, calls the CA revocation API,
 * and responds with CERT_REVOCATION_RESPONSE (or AGENT_ERROR on failure).
 *
 * <p>{@code userId} is included for traceability only.
 *
 * <p>For DigiCert, {@code caCredentialHandle} must be the KV URI of the CA credential
 * (same pattern as {@link CertIssuanceMessage#getCaCredentialHandle()}).
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertRevocationMessage {
    private String     requestId;
    private String     correlationId;
    private String     organizationId;
    private String     certificateXref;
    private String     domain;
    private CaProvider caProvider;
    private String     certSecretHandle;
    /** DigiCert order ID — null for Let's Encrypt. */
    private String     orderId;
    private String     revocationReason;
    private String     requestedAt;
    private Integer    userId;
    /** KV URI for CA credential — required when {@code caProvider} is DIGICERT. */
    private String     caCredentialHandle;
}
