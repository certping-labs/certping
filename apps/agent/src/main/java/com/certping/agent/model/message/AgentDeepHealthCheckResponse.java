// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
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
