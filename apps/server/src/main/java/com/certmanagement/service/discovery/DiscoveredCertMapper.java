// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.dto.discovery.DiscoveredCertDetailDto;
import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.entity.DiscoveryInventoryStatus;
import com.certmanagement.messaging.model.DiscoveredCertEntry;
import com.certmanagement.messaging.model.KubernetesDiscoveryData;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;

@Component
public class DiscoveredCertMapper {

    private static final String TARGET_KUBERNETES_SECRETS = "KUBERNETES_SECRETS";

    public DiscoveredCertEntity buildOrUpdate(
            DiscoveredCertEntity existing,
            Long organizationId,
            String requestId,
            String targetType,
            DiscoveredCertEntry entry,
            OffsetDateTime discoveredAt,
            Set<String> managedSerials) {
        String normalizedSerial = DiscoveryService.normalizeSerial(entry.getSerialNumber());
        Boolean isManaged = normalizedSerial.isEmpty() ? null : managedSerials.contains(normalizedSerial);
        DiscoveredCertEntity entity = existing != null ? existing : new DiscoveredCertEntity();
        entity.setOrganizationId(organizationId);
        entity.setRequestId(requestId);
        entity.setTargetType(targetType);
        entity.setResourceId(entry.getResourceId());
        entity.setDomain(entry.getDomain());
        entity.setSubjectDn(entry.getSubjectDn());
        entity.setSanDomains(toArray(entry.getSanDomains()));
        entity.setKeyAlgorithm(entry.getKeyAlgorithm());
        entity.setSignatureAlgorithm(entry.getSignatureAlgorithm());
        entity.setNotBefore(parseDateTime(entry.getNotBefore()));
        entity.setNotAfter(parseDateTime(entry.getNotAfter()));
        entity.setIssuer(entry.getIssuer());
        entity.setSerialNumber(entry.getSerialNumber());
        entity.setCertStatus(entry.getCertStatus());
        entity.setInUseBy(toArray(entry.getInUseBy()));
        entity.setKeyUsage(entry.getKeyUsage());
        entity.setExtendedKeyUsage(entry.getExtendedKeyUsage());
        entity.setCertType(entry.getCertType());
        entity.setProviderData(TARGET_KUBERNETES_SECRETS.equals(targetType) ? entry.getKubernetesData() : null);
        entity.setInventoryStatus(DiscoveryInventoryStatus.PRESENT);
        entity.setMissingSince(null);
        entity.setManaged(isManaged);
        entity.setDiscoveredAt(discoveredAt);
        return entity;
    }

    public DiscoveredCertDetailDto toDetailDto(
            DiscoveredCertEntity entity, KubernetesDiscoveryData providerData) {
        return DiscoveredCertDetailDto.builder()
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
                .inUseBy(toList(entity.getInUseBy()))
                .subjectDn(entity.getSubjectDn())
                .sanDomains(toList(entity.getSanDomains()))
                .keyUsage(entity.getKeyUsage())
                .extendedKeyUsage(entity.getExtendedKeyUsage())
                .certType(entity.getCertType())
                .inventoryStatus(entity.getInventoryStatus().name())
                .missingSince(entity.getMissingSince())
                .managed(entity.getManaged())
                .discoveredAt(entity.getDiscoveredAt())
                .providerData(providerData)
                .build();
    }

    private OffsetDateTime parseDateTime(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (Exception exception) {
            return null;
        }
    }

    private String[] toArray(List<String> values) {
        return values != null ? values.toArray(String[]::new) : new String[0];
    }

    private List<String> toList(String[] values) {
        return values != null ? List.of(values) : List.of();
    }
}
