// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.discovery;

import com.certmanagement.entity.DiscoveredCertEntity;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Value;

import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.List;

/**
 * API response representation of a discovered certificate.
 *
 * <p>Derived from {@link DiscoveredCertEntity}; exposes all discovery metadata
 * plus the {@code managed} flag so the UI can distinguish CertPing-managed certs
 * from externally-managed ones.
 */
@Value
@Jacksonized
@Builder
public class DiscoveredCertDto {

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

    /**
     * True = managed by CertPing, false = externally managed, null = not yet evaluated.
     */
    Boolean managed;

    /**
     * When {@code managed} is true, the xref of the CertPing certificate this discovered
     * cert maps to (matched by serial number), so the UI can deep-link to its detail page.
     * Null for external certs or when the matching certificate can no longer be resolved.
     */
    String managedCertificateXref;

    /**
     * The xref of the deployment credential that discovered this certificate, taken from the
     * most recent {@code discovered_cert_observation}, so the UI can show and deep-link to the
     * credential under the source. Null when no observation can be resolved.
     */
    String credentialXref;
    OffsetDateTime discoveredAt;

    public static DiscoveredCertDto from(DiscoveredCertEntity entity) {
        return from(entity, null, null);
    }

    public static DiscoveredCertDto from(DiscoveredCertEntity entity, String managedCertificateXref,
                                         String credentialXref) {
        return DiscoveredCertDto.builder()
                .id(entity.getId())
                .organizationId(entity.getOrganizationId())
                .targetType(entity.getTargetType())
                .resourceId(entity.getResourceId())
                .domain(entity.getDomain())
                .keyAlgorithm(entity.getKeyAlgorithm())
                .signatureAlgorithm(entity.getSignatureAlgorithm())
                .notBefore(entity.getNotBefore())
                .notAfter(entity.getNotAfter())
                .issuer(entity.getIssuer())
                .serialNumber(entity.getSerialNumber())
                .certStatus(entity.getCertStatus())
                .inUseBy(entity.getInUseBy() != null ? Arrays.asList(entity.getInUseBy()) : List.of())
                .subjectDn(entity.getSubjectDn())
                .sanDomains(entity.getSanDomains() != null ? Arrays.asList(entity.getSanDomains()) : List.of())
                .keyUsage(entity.getKeyUsage())
                .extendedKeyUsage(entity.getExtendedKeyUsage())
                .certType(entity.getCertType())
                .inventoryStatus(entity.getInventoryStatus().name())
                .missingSince(entity.getMissingSince())
                .managed(entity.getManaged())
                .managedCertificateXref(managedCertificateXref)
                .credentialXref(credentialXref)
                .discoveredAt(entity.getDiscoveredAt())
                .build();
    }
}
