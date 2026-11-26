// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.discovery;

import com.certmanagement.messaging.model.ProviderDiscoveryData;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Value;

import java.time.OffsetDateTime;
import java.util.List;

@Value
@Jacksonized
@Builder
public class DiscoveredCertDetailDto {

    Long id;
    Long organizationId;
    String targetType;
    String resourceId;
    String domain;
    String keyAlgorithm;
    String signatureAlgorithm;
    OffsetDateTime notBefore;
    OffsetDateTime notAfter;
    String issuer;
    String serialNumber;
    String certStatus;
    List<String> inUseBy;
    String subjectDn;
    List<String> sanDomains;
    String keyUsage;
    String extendedKeyUsage;
    String certType;
    String inventoryStatus;
    OffsetDateTime missingSince;
    Boolean managed;
    OffsetDateTime discoveredAt;
    ProviderDiscoveryData providerData;
}
