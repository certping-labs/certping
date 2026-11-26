// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentDeepHealthCheckMessage {
    private String deepCheckId;
    private String requestId;
    private String correlationId;
    private String organizationId;
    private Integer chunkIndex;
    private Integer totalChunks;
    private String requestedAt;
    private List<String> secretHandles;
}
