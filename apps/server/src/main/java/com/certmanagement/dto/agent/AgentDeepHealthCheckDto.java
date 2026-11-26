// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import com.certmanagement.enums.AgentDeepHealthCheckStatus;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@Jacksonized
@Builder
public class AgentDeepHealthCheckDto {
    private String deepCheckId;
    private String requestId;
    private String correlationId;
    private AgentDeepHealthCheckStatus status;
    private Integer expectedChunks;
    private Integer receivedChunks;
    private OffsetDateTime requestedAt;
    private OffsetDateTime startedAt;
    private OffsetDateTime completedAt;
    private OffsetDateTime lastRespondedAt;
    private String errorCode;
    private String errorMessage;
}
