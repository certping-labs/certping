// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.featureflags.FeatureFlagDto;
import com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminFeatureFlagControllerMoreTest {

    @Mock private FeatureFlagService featureFlagService;
    @Mock private OrganizationRepository organizationRepository;

    private AdminFeatureFlagController controller;

    @BeforeEach
    void setUp() {
        controller = new AdminFeatureFlagController(featureFlagService, organizationRepository, org.mockito.Mockito.mock(com.certmanagement.service.lifecycle.FeatureImpactService.class));
    }

    private GlobalFeatureFlag global(String key, String scope) {
        return GlobalFeatureFlag.builder()
                .featureKey(key).scope(scope).category("CERT").enabled(true).build();
    }

    private FeatureFlagUpdateRequest updateRequest(boolean enabled, String reason) {
        FeatureFlagUpdateRequest req = new FeatureFlagUpdateRequest();
        req.setEnabled(enabled);
        req.setReason(reason);
        return req;
    }

    @Test
    void listFlagsForOrg_filtersToOrgScopeFlags() {
        GlobalFeatureFlag orgFlag = global("ORG_FLAG", "ORG");
        GlobalFeatureFlag platformFlag = global("PLATFORM_FLAG", "PLATFORM");
        when(featureFlagService.listEffective(5L)).thenReturn(List.of(
                new FeatureFlagService.ResolvedFlag(orgFlag, true, null, "B2B", true, true, false),
                new FeatureFlagService.ResolvedFlag(platformFlag, null, null, "B2B", true, false, false)));

        ResponseEntity<Map<String, Object>> resp = controller.listFlagsForOrg(5L);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        @SuppressWarnings("unchecked")
        List<FeatureFlagDto> flags = (List<FeatureFlagDto>) resp.getBody().get("flags");
        assertThat(flags).hasSize(1);
        assertThat(flags.get(0).getFeatureKey()).isEqualTo("ORG_FLAG");
    }

    @Test
    void summary_buildsMatrixForEveryOrgAndFlag() {
        Organization org = Organization.builder().id(5L).name("Acme").orgType("B2B").build();
        when(organizationRepository.findByActiveTrue()).thenReturn(List.of(org));
        GlobalFeatureFlag g = global("ORG_FLAG", "ORG");
        when(featureFlagService.listGlobal()).thenReturn(List.of(g));
        when(featureFlagService.listEffectiveForOrganizations(Map.of(5L, "B2B"))).thenReturn(Map.of(5L, List.of(
                new FeatureFlagService.ResolvedFlag(g, true, false, "B2B", true, true, false))));

        ResponseEntity<?> resp = controller.summary();

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat((List<?>) resp.getBody()).hasSize(1);
        // One batch resolution for the whole matrix, never one listEffective round per organization.
        verify(featureFlagService, never()).listEffective(5L);
    }

    @Test
    void summary_missingResolvedFlag_fallsBackToGlobalEnabled() {
        Organization org = Organization.builder().id(5L).name("Acme").orgType("B2B").build();
        when(organizationRepository.findByActiveTrue()).thenReturn(List.of(org));
        when(featureFlagService.listGlobal()).thenReturn(List.of(global("ORG_FLAG", "ORG")));
        when(featureFlagService.listEffectiveForOrganizations(Map.of(5L, "B2B")))
                .thenReturn(Map.of(5L, List.of())); // no resolved → fallback path

        ResponseEntity<?> resp = controller.summary();

        assertThat((List<?>) resp.getBody()).hasSize(1);
    }

    @Test
    void updateGlobal_delegates() {
        GlobalFeatureFlag updated = global("KEY", "ORG");
        when(featureFlagService.updateGlobal("KEY", true, "reason")).thenReturn(updated);

        ResponseEntity<GlobalFeatureFlag> resp = controller.updateGlobal("KEY", updateRequest(true, "reason"));

        assertThat(resp.getBody()).isEqualTo(updated);
    }

    @Test
    void removeOrgTypeFlag_returnsRemovedFlag() {
        when(featureFlagService.removeOrgTypeOverride("B2B", "KEY", null)).thenReturn(true);

        ResponseEntity<Map<String, Object>> resp = controller.removeOrgTypeFlag("KEY", "B2B", null);

        assertThat(resp.getBody()).containsEntry("removed", true);
        assertThat(resp.getBody()).containsEntry("featureKey", "KEY");
        assertThat(resp.getBody()).containsEntry("orgType", "B2B");
    }

    @Test
    void updateOrgFlagAsAdmin_setsALockedOverride() {
        OrganizationFeatureFlag saved = OrganizationFeatureFlag.builder().featureKey("KEY").adminLocked(true).build();
        when(featureFlagService.upsertOrgOverrideAsAdmin(5L, "KEY", true, null)).thenReturn(saved);
        GlobalFeatureFlag g = global("KEY", "ORG");
        when(featureFlagService.listEffective(5L)).thenReturn(List.of(
                new FeatureFlagService.ResolvedFlag(g, true, null, "B2B", true, false, true)));

        ResponseEntity<FeatureFlagDto> resp = controller.updateOrgFlagAsAdmin("KEY", 5L, updateRequest(true, null));

        assertThat(resp.getBody().getFeatureKey()).isEqualTo("KEY");
        assertThat(resp.getBody().isAdminLocked()).isTrue();
        verify(featureFlagService, never()).upsertOrgOverride(any(), any(), anyBoolean(), any());
    }

    @Test
    void listOverrides_returnsPage() {
        Page<OrganizationFeatureFlag> page = new PageImpl<>(List.of(
                OrganizationFeatureFlag.builder().featureKey("KEY").build()));
        when(featureFlagService.listOrgOverrides(eq("KEY"), any())).thenReturn(page);

        ResponseEntity<Page<OrganizationFeatureFlag>> resp =
                controller.listOverrides("KEY", PageRequest.of(0, 20));

        assertThat(resp.getBody().getTotalElements()).isEqualTo(1);
    }

    @Test
    void removeOrgOverride_returnsResultMap() {
        when(featureFlagService.removeOrgOverrideAsAdmin(5L, "KEY", null)).thenReturn(false);

        ResponseEntity<Map<String, Object>> resp = controller.removeOrgOverride("KEY", 5L, null);

        assertThat(resp.getBody()).containsEntry("removed", false);
        assertThat(resp.getBody()).containsEntry("organizationId", 5L);
    }
}
