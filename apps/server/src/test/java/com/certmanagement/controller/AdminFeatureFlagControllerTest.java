// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminFeatureFlagControllerTest {

    @Mock private FeatureFlagService     featureFlagService;
    @Mock private OrganizationRepository organizationRepository;

    @Mock private com.certmanagement.service.lifecycle.FeatureImpactService featureImpactService;

    @InjectMocks private AdminFeatureFlagController controller;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    // ── bulkUpdateOrgTypeFlags ────────────────────────────────────────────

    @Test
    void bulkUpdateOrgTypeFlags_delegatesAndReturns200() {
        OrgTypeFeatureFlag flagA = OrgTypeFeatureFlag.builder()
                .orgType("B2B").featureKey("feat.a").enabled(true).build();
        OrgTypeFeatureFlag flagB = OrgTypeFeatureFlag.builder()
                .orgType("B2B").featureKey("feat.b").enabled(true).build();

        when(featureFlagService.bulkSetOrgTypeOverrides("B2B", true, null))
                .thenReturn(List.of(flagA, flagB));

        FeatureFlagUpdateRequest request = new FeatureFlagUpdateRequest();
        request.setEnabled(true);

        ResponseEntity<List<OrgTypeFeatureFlag>> response =
                controller.bulkUpdateOrgTypeFlags("B2B", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsExactly(flagA, flagB);
        verify(featureFlagService).bulkSetOrgTypeOverrides("B2B", true, null);
    }

    @Test
    void bulkUpdateOrgTypeFlags_disableAll_passesFalseToService() {
        when(featureFlagService.bulkSetOrgTypeOverrides("B2B", false, null))
                .thenReturn(List.of());

        FeatureFlagUpdateRequest request = new FeatureFlagUpdateRequest();
        request.setEnabled(false);

        ResponseEntity<List<OrgTypeFeatureFlag>> response =
                controller.bulkUpdateOrgTypeFlags("B2B", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEmpty();
        verify(featureFlagService).bulkSetOrgTypeOverrides("B2B", false, null);
    }

    @Test
    void everyEndpointIsGatedOnTheSuperAdminRoleAlone() {
        assertThat(AdminFeatureFlagController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasRole('SUPER_ADMIN')");
        assertThat(AdminFeatureFlagController.class.getDeclaredMethods())
                .as("a method-level @PreAuthorize would replace the class-level role check")
                .noneMatch(method -> method.isAnnotationPresent(PreAuthorize.class));
    }

    // ── listGlobal ────────────────────────────────────────────────────────

    @Test
    void listGlobal_returnsAllFlags() {
        GlobalFeatureFlag flag = GlobalFeatureFlag.builder()
                .featureKey("feat.x").scope("ORG").category("PLATFORM").enabled(true).build();
        when(featureFlagService.listGlobal()).thenReturn(List.of(flag));

        ResponseEntity<List<GlobalFeatureFlag>> response = controller.listGlobal();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsExactly(flag);
    }

    // ── listOrgTypeOverrides ──────────────────────────────────────────────

    @Test
    void listOrgTypeOverrides_delegatesToService() {
        OrgTypeFeatureFlag override = OrgTypeFeatureFlag.builder()
                .orgType("B2B").featureKey("feat.x").enabled(false).build();
        when(featureFlagService.listOrgTypeEffective("B2B")).thenReturn(List.of(override));

        ResponseEntity<List<OrgTypeFeatureFlag>> response =
                controller.listOrgTypeOverrides("B2B");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsExactly(override);
    }

    // ── updateOrgTypeFlag ─────────────────────────────────────────────────

    @Test
    void updateOrgTypeFlag_delegatesAndReturns200() {
        OrgTypeFeatureFlag saved = OrgTypeFeatureFlag.builder()
                .orgType("B2B").featureKey("feat.a").enabled(false).build();
        when(featureFlagService.upsertOrgTypeOverride("B2B", "feat.a", false, null))
                .thenReturn(saved);

        FeatureFlagUpdateRequest request = new FeatureFlagUpdateRequest();
        request.setEnabled(false);

        ResponseEntity<OrgTypeFeatureFlag> response =
                controller.updateOrgTypeFlag("feat.a", "B2B", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(saved);
        verify(featureFlagService).upsertOrgTypeOverride("B2B", "feat.a", false, null);
    }
}
