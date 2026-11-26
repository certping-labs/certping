// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

// Agent → server. MessageType = CERT_SECRET_DELETE_RESPONSE.
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertSecretDeleteResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    // "SUCCESS" or "FAILED".
    private String status;
    private String errorCode;
    private String errorDetail;
    private String respondedAt;
}
