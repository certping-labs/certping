// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertificateProfileOperationResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String profileXref;
    private String operationXref;
    private Long desiredRevision;
    private String status;
    private String errorCode;
    private String errorMessage;
    private ProfileObservedState profile;
    private String respondedAt;
}
