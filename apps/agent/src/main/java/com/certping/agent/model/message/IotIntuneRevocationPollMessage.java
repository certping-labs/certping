// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class IotIntuneRevocationPollMessage {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String connectionProfileRef;
    private String transactionId;
    private Integer dispatchAttempt;
    private Integer maxRequests;
}
