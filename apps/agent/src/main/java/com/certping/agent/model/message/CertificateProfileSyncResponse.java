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
public class CertificateProfileSyncResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private Integer batchIndex;
    private String batchChecksum;
    private List<ProfileObservedState> profiles;
    private String respondedAt;
}
