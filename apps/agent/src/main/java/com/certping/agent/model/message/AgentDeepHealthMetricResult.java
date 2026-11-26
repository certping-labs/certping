// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AgentDeepHealthMetricResult {
    private String metricKey;
    private String metricName;
    private String metricGroup;
    private String status;
    private String path;
    private String message;
    private String details;
}
