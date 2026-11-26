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
public class AgentDeepHealthTriggerResponseDto {
    private String deepCheckId;
    private AgentDeepHealthCheckStatus status;
    private OffsetDateTime requestedAt;
}
