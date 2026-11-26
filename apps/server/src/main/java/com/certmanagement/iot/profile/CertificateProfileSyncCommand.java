// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

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
public class CertificateProfileSyncCommand {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String orgType;
    private String sourceXref;
    private String connectionProfileRef;
    private String provider;
    private List<CertificateCorrelationCandidate> certificateCorrelationCandidates;
    private String requestedAt;
}
