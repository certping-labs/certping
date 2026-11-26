// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/** Agent-owned health observation for one locally configured device-source profile. */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
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
