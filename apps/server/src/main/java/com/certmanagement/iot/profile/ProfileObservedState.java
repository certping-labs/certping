// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProfileObservedState {
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
    private Map<String, Object> providerResponse;
    private String providerVersion;
    private String providerLastModifiedAt;
    private String observedAt;
}
