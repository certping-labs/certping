// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertSecretDeleteResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String status;
    private String errorCode;
    private String errorDetail;
    private String respondedAt;
}
