// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.featureflags.FeatureFlagDto;
import com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureFlagControllerMoreTest {

    @Mock private FeatureFlagService featureFlagService;

    private FeatureFlagController controller;

    private static final Long ORG_ID = 100L;

    @BeforeEach
    void setUp() {
        controller = new FeatureFlagController(featureFlagService, org.mockito.Mockito.mock(com.certmanagement.service.lifecycle.FeatureLifecycleService.class));
        GatewayRequestContext.set(7, String.valueOf(ORG_ID), "req-1", "user@example.com");
        org.mockito.Mockito.lenient().when(featureFlagService.isEnabled(
                com.certmanagement.constants.FeatureFlags.FEATURE_FLAGS_PAGE, ORG_ID)).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private FeatureFlagService.ResolvedFlag resolved(String key) {
        GlobalFeatureFlag g = GlobalFeatureFlag.builder()
                .featureKey(key).scope("ORG").category("B2B").enabled(true).build();
        return new FeatureFlagService.ResolvedFlag(g, true, null, "B2B", true, true, false);
    }

    @Test
    void updateOrgFlag_upsertsAndReturnsDto() {
        OrganizationFeatureFlag saved = OrganizationFeatureFlag.builder().featureKey("KEY").build();
        when(featureFlagService.upsertOrgOverride(ORG_ID, "KEY", true, null)).thenReturn(saved);
        when(featureFlagService.listEffective(ORG_ID)).thenReturn(List.of(resolved("KEY")));

        FeatureFlagUpdateRequest req = new FeatureFlagUpdateRequest();
        req.setEnabled(true);

        ResponseEntity<FeatureFlagDto> resp = controller.updateOrgFlag("KEY", req);

        assertThat(resp.getBody().getFeatureKey()).isEqualTo("KEY");
    }

    @Test
    void removeOrgFlag_removed_returnsRemovedTrueMessage() {
        when(featureFlagService.removeOrgOverride(ORG_ID, "KEY", null)).thenReturn(true);

        ResponseEntity<Map<String, Object>> resp = controller.removeOrgFlag("KEY", null);

        assertThat(resp.getBody()).containsEntry("removed", true);
        assertThat((String) resp.getBody().get("message")).contains("Override removed");
    }

    @Test
    void removeOrgFlag_notRemoved_returnsRemovedFalseMessage() {
        when(featureFlagService.removeOrgOverride(ORG_ID, "KEY", null)).thenReturn(false);

        ResponseEntity<Map<String, Object>> resp = controller.removeOrgFlag("KEY", null);

        assertThat(resp.getBody()).containsEntry("removed", false);
        assertThat((String) resp.getBody().get("message")).contains("No override found");
    }
}
