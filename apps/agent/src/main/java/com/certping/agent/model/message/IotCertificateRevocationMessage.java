// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class IotCertificateRevocationMessage {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String operationXref;
    private Integer dispatchAttempt;
    private String certificateXref;
    private String caProvider;
    private String issuerDn;
    private String serialNumber;
    private String reason;
    private String requestedAt;
}
