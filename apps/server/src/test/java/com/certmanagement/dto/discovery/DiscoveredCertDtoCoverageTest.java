// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.discovery;

import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.entity.DiscoveryInventoryStatus;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveredCertDtoCoverageTest {

    private DiscoveredCertEntity entity(String[] inUse, String[] sans) {
        OffsetDateTime now = OffsetDateTime.now();
        return DiscoveredCertEntity.builder()
                .id(1L)
                .organizationId(7L)
                .targetType("AZURE")
                .resourceId("res")
                .domain("a.com")
                .keyAlgorithm("RSA")
                .signatureAlgorithm("SHA256")
                .notBefore(now)
                .notAfter(now.plusDays(90))
                .issuer("CA")
                .serialNumber("SN1")
                .certStatus("VALID")
                .inUseBy(inUse)
                .subjectDn("CN=a.com")
                .sanDomains(sans)
                .keyUsage("ku")
                .extendedKeyUsage("eku")
                .certType("DV")
                .inventoryStatus(DiscoveryInventoryStatus.PRESENT)
                .missingSince(null)
                .managed(true)
                .discoveredAt(now)
                .build();
    }

    @Test
    void fromEntityWithArrays() {
        DiscoveredCertEntity e = entity(new String[]{"lb1"}, new String[]{"a.com", "b.com"});
        DiscoveredCertDto dto = DiscoveredCertDto.from(e, "xref-9", null);

        assertThat(dto.getId()).isEqualTo(1L);
        assertThat(dto.getOrganizationId()).isEqualTo(7L);
        assertThat(dto.getTargetType()).isEqualTo("AZURE");
        assertThat(dto.getDomain()).isEqualTo("a.com");
        assertThat(dto.getInUseBy()).containsExactly("lb1");
        assertThat(dto.getSanDomains()).containsExactly("a.com", "b.com");
        assertThat(dto.getInventoryStatus()).isEqualTo("PRESENT");
        assertThat(dto.getManaged()).isTrue();
        assertThat(dto.getManagedCertificateXref()).isEqualTo("xref-9");
        assertThat(dto.getKeyUsage()).isEqualTo("ku");
        assertThat(dto.getExtendedKeyUsage()).isEqualTo("eku");
        assertThat(dto.getCertType()).isEqualTo("DV");
    }

    @Test
    void fromEntityWithNullArraysUsesEmptyLists() {
        DiscoveredCertEntity e = entity(null, null);
        DiscoveredCertDto dto = DiscoveredCertDto.from(e);

        assertThat(dto.getInUseBy()).isEmpty();
        assertThat(dto.getSanDomains()).isEmpty();
        assertThat(dto.getManagedCertificateXref()).isNull();
    }

    @Test
    void builderAndValueSemantics() {
        DiscoveredCertDto a = DiscoveredCertDto.builder().id(5L).domain("x.com").build();
        DiscoveredCertDto b = DiscoveredCertDto.builder().id(5L).domain("x.com").build();
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        assertThat(a.toString()).contains("x.com");
    }
}
