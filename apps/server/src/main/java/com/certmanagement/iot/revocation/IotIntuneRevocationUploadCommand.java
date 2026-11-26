// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.util.List;

@Data
@Jacksonized
@Builder
public class IotIntuneRevocationUploadCommand {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String orgType;
    private String sourceXref;
    private String connectionProfileRef;
    private String transactionId;
    private Integer dispatchAttempt;
    private List<Result> results;

    public record Result(String requestContext, boolean succeeded,
                         String errorCode, String errorMessage) {}
}
