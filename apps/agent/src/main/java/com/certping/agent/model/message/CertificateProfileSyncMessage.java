// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

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
public class CertificateProfileSyncMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String connectionProfileRef;
    private String provider;
    private List<CertificateCorrelationCandidate> certificateCorrelationCandidates;
    private String requestedAt;
}
