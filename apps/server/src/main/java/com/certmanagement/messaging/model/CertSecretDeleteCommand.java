// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

// Server → agent. MessageType = CERT_SECRET_DELETE_COMMAND.
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertSecretDeleteCommand {
    private String requestId;
    private String correlationId;
    private String organizationId;
    // Org type, always "B2B"; kept because the agent's message contract carries it.
    private String orgType;
    private String certificateXref;
    private String certSecretHandle;
    private String requestedAt;
}
