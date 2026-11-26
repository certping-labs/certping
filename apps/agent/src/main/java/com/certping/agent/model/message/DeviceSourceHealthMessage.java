// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class DeviceSourceHealthMessage {
    private String healthXref;
    private String correlationId;
    private String organizationId;
    private String connectionProfileRef;
    private String provider;
    private String sourceCategory;
    private String displayName;
    private String description;
    private Map<String, Object> configurationMetadata;
    private String healthStatus;
    private String providerStatus;
    private String statusMessage;
    private Map<String, Object> healthMetadata;
    private String agentInstanceXref;
    private Long agentSequence;
    private String checkStartedAt;
    private String observedAt;
    private String publishedAt;
    private Long responseTimeMs;
}
