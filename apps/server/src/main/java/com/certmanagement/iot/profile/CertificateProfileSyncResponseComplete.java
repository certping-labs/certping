// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertificateProfileSyncResponseComplete {
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
