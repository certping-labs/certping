// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import com.certmanagement.enums.AgentHealthOverallStatus;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@Jacksonized
@Builder
public class AgentHealthResponseDto {
    private Long organizationId;
    private AgentHealthOverallStatus overallStatus;
    private Boolean listening;
    private OffsetDateTime checkedAt;
    private boolean stale;
    private String failureReason;
}
