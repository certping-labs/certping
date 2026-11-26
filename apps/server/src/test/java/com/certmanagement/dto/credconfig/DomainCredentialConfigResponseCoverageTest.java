// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig;

import com.certmanagement.entity.DomainCredentialConfigEntity;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DomainCredentialConfigResponseCoverageTest {

    @Test
    void fromEntity() {
        OffsetDateTime now = OffsetDateTime.now();
        DomainCredentialConfigEntity entity = DomainCredentialConfigEntity.builder()
                .id(11L)
                .userDomainCertId(22L)
                .dnsConfig(Map.of("a.com", "cred-a"))
                .deploymentTargets(List.of("dep-1", "dep-2"))
                .updatedAt(now)
                .build();

        DomainCredentialConfigResponse r = DomainCredentialConfigResponse.from(entity);
        assertThat(r.getId()).isEqualTo(11L);
        assertThat(r.getUserDomainCertId()).isEqualTo(22L);
        assertThat(r.getDnsConfig()).containsEntry("a.com", "cred-a");
        assertThat(r.getDeploymentTargets()).containsExactly("dep-1", "dep-2");
        assertThat(r.getUpdatedAt()).isEqualTo(now);
    }

    @Test
    void builderDirect() {
        DomainCredentialConfigResponse r = DomainCredentialConfigResponse.builder()
                .id(1L)
                .build();
        assertThat(r.getId()).isEqualTo(1L);
        assertThat(r.toString()).contains("1");
    }
}
