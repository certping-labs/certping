// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class IotIntuneRevocationUploadResponse {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String transactionId;
    private Integer dispatchAttempt;
    private String outcome;
    private String errorCode;
    private String errorMessage;
}
