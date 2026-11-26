// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

/**
 * Outbound response — Agent → Server.
 * MessageType = "CERT_REVOCATION_RESPONSE"
 *
 * <p>Sent on successful CA revocation (including when the CA reports already-revoked).
 * On failure, the listener sends AGENT_ERROR instead.
 */
@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertRevocationResponse {
    private String     requestId;
    private String     correlationId;
    private String     organizationId;
    private String     certificateXref;
    private CaProvider caProvider;
    private String     revocationReason;
    private String     revokedAt;
}
