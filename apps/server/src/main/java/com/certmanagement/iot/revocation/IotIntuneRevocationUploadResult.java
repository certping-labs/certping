// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class IotIntuneRevocationUploadResult {
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
