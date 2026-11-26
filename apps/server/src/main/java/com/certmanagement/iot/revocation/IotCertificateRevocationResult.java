// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class IotCertificateRevocationResult {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String operationXref;
    private Integer dispatchAttempt;
    private String certificateXref;
    private String outcome;
    private String reason;
    private String caObservedReason;
    private String observedAt;
    private String errorCode;
    private String errorMessage;
}
