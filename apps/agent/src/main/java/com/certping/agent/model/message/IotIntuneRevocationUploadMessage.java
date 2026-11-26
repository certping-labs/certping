// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.platform.intune.IntuneRevocationClient;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class IotIntuneRevocationUploadMessage {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String connectionProfileRef;
    private String transactionId;
    private Integer dispatchAttempt;
    private List<IntuneRevocationClient.RevocationResult> results;
}
