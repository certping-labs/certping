// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

@Data
@Jacksonized
@Builder
public class IotCertificateRevocationCommand {
    private Integer messageVersion;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String orgType;
    private String operationXref;
    private Integer dispatchAttempt;
    private String certificateXref;
    private String caProvider;
    private String issuerDn;
    private String serialNumber;
    private String reason;
    private String requestedAt;
}
