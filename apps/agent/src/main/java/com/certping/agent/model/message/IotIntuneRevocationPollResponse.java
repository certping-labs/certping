// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.platform.intune.IntuneRevocationClient;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class IotIntuneRevocationPollResponse {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String transactionId;
    private Integer dispatchAttempt;
    private Boolean redelivered;
    private String outcome;
    private List<IntuneRevocationClient.RevocationRequest> requests;
    private String errorCode;
    private String errorMessage;
}
