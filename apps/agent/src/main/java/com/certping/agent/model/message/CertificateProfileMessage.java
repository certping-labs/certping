// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertificateProfileMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String connectionProfileRef;
    private String provider;
    private String profileXref;
    private String operationXref;
    private String operation;
    private Long desiredRevision;
    private String providerProfileId;
    private String providerProfileType;
    private String providerCorrelationMarker;
    private String name;
    private String description;
    private String targetPlatform;
    private String targetVariant;
    private String profileKind;
    private String enrollmentMethod;
    private Map<String, Object> configuration;
    private String requestedAt;
}
