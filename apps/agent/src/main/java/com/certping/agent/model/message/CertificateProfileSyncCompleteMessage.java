// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertificateProfileSyncCompleteMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private Integer totalProfiles;
    private Integer totalBatches;
    private String status;
    private String errorCode;
    private String errorMessage;
    private List<CertificateCorrelationResult> certificateCorrelations;
    private String completedAt;
}
