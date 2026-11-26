// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class IotIntuneRevocationPollResult {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String transactionId;
    private Integer dispatchAttempt;
    private Boolean redelivered;
    private String outcome;
    private List<Request> requests;
    private String errorCode;
    private String errorMessage;

    @Data
    @NoArgsConstructor
    public static class Request {
        private String requestContext;
        private String serialNumber;
        private String issuerName;
        private String caConfiguration;
    }
}
