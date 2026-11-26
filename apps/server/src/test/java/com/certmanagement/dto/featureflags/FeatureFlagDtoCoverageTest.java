// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.service.FeatureFlagService.ResolvedFlag;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FeatureFlagDtoCoverageTest {

    @Test
    void fromResolvedFlag() {
        GlobalFeatureFlag g = GlobalFeatureFlag.builder()
                .featureKey("discovery")
                .displayName("Certificate Discovery")
                .description("desc")
                .scope("ORG")
                .category("B2B")
                .enabled(true)
                .build();

        ResolvedFlag resolved = new ResolvedFlag(g, Boolean.TRUE, Boolean.FALSE, "B2B", true, true, true);
        FeatureFlagDto dto = FeatureFlagDto.from(resolved);

        assertThat(dto.getFeatureKey()).isEqualTo("discovery");
        assertThat(dto.getDisplayName()).isEqualTo("Certificate Discovery");
        assertThat(dto.getDescription()).isEqualTo("desc");
        assertThat(dto.getScope()).isEqualTo("ORG");
        assertThat(dto.getCategory()).isEqualTo("B2B");
        assertThat(dto.isGlobalEnabled()).isTrue();
        assertThat(dto.getOrgType()).isEqualTo("B2B");
        assertThat(dto.getOrgTypeEnabled()).isFalse();
        assertThat(dto.getOrgEnabled()).isTrue();
        assertThat(dto.isAdminLocked()).isTrue();
        assertThat(dto.isEffectiveEnabled()).isTrue();
    }

    @Test
    void fromResolvedFlagDisabledGlobal() {
        GlobalFeatureFlag g = GlobalFeatureFlag.builder()
                .featureKey("k")
                .enabled(false)
                .build();
        ResolvedFlag resolved = new ResolvedFlag(g, null, null, "B2B", false, false, false);
        FeatureFlagDto dto = FeatureFlagDto.from(resolved);
        assertThat(dto.isGlobalEnabled()).isFalse();
        assertThat(dto.getOrgEnabled()).isNull();
        assertThat(dto.getOrgTypeEnabled()).isNull();
        assertThat(dto.isEffectiveEnabled()).isFalse();
    }

    @Test
    void fromResolvedFlagWhoseAutomaticWorkIsPaused() {
        GlobalFeatureFlag g = GlobalFeatureFlag.builder().featureKey("CERTIFICATE_RENEWAL").enabled(true).build();
        ResolvedFlag resolved = new ResolvedFlag(g, null, null, "B2B", true, false, false, "DNS_CREDENTIALS");

        FeatureFlagDto dto = FeatureFlagDto.from(resolved);

        assertThat(dto.isEffectiveEnabled()).isTrue();
        assertThat(dto.getAutomaticWorkPausedBy()).isEqualTo("DNS_CREDENTIALS");
    }

    @Test
    void builderDirect() {
        FeatureFlagDto dto = FeatureFlagDto.builder()
                .featureKey("k")
                .globalEnabled(true)
                .effectiveEnabled(true)
                .build();
        assertThat(dto.getFeatureKey()).isEqualTo("k");
        assertThat(dto.toString()).contains("k");
    }
}
