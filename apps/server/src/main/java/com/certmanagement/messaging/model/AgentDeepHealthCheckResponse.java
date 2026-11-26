// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentDeepHealthCheckResponse {
    private String deepCheckId;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String status;
    private Integer chunkIndex;
    private Integer totalChunks;
    private String respondedAt;
    private String errorCode;
    private String errorMessage;
    private List<AgentDeepHealthMetricResult> metrics;
}
