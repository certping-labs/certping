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
public class CertificateProfileSyncResponsePart {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private Integer batchIndex;
    private String batchChecksum;
    private List<ProfileObservedState> profiles;
    private String respondedAt;
}
