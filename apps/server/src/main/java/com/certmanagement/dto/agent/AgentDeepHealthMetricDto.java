// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import com.certmanagement.enums.AgentDeepHealthMetricStatus;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@Jacksonized
@Builder
public class AgentDeepHealthMetricDto {
    private String metricKey;
    private String metricName;
    private String metricGroup;
    private AgentDeepHealthMetricStatus status;
    private String path;
    private String message;
    private String details;
    private OffsetDateTime respondedAt;
}
