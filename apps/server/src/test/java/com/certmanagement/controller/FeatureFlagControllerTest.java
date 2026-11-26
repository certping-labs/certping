// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.exception.ManagedByCertpingException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.FeatureFlagService.ResolvedFlag;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureFlagControllerTest {

    @Mock private FeatureFlagService featureFlagService;

    @Mock private com.certmanagement.service.lifecycle.FeatureLifecycleService lifecycleService;

    @InjectMocks private FeatureFlagController controller;

    @BeforeEach
    void setUp() {
        // listFlags() resolves the org from the JWT via OrgResolver.fromJwt(),
        // which reads GatewayRequestContext. Seed an org so the call resolves.
        GatewayRequestContext.set(7, "100", "req-test", "user@example.com");
        org.mockito.Mockito.lenient().when(featureFlagService.isEnabled(FeatureFlags.FEATURE_FLAGS_PAGE, 100L))
                .thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private static ResolvedFlag resolved(String key, String scope, boolean effective) {
        return resolved(key, scope, true, effective, "ORG".equals(scope));
    }

    private static ResolvedFlag resolved(String key, String scope, boolean globalEnabled, boolean effective,
                                         boolean orgControllable) {
        GlobalFeatureFlag global = GlobalFeatureFlag.builder()
                .featureKey(key)
                .displayName(key)
                .description("")
                .scope(scope)
                .category("B2B")
                .enabled(globalEnabled)
                .build();
        return new ResolvedFlag(global, null, null, "B2B", effective, orgControllable, false);
    }

    private static ResolvedFlag managed(String key, boolean effective) {
        GlobalFeatureFlag global = GlobalFeatureFlag.builder()
                .featureKey(key).displayName(key).description("").scope("ORG").category("PLATFORM").enabled(true)
                .build();
        return new ResolvedFlag(global, null, null, "B2B", effective, false, false);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listFlags_includesPlatformFlagsInEffectiveMapButNotInManageableList() {
        when(featureFlagService.listEffective(100L)).thenReturn(List.of(
                resolved("DISCOVERY", "ORG", true),
                resolved("PQC_READINESS", "PLATFORM", false),
                resolved("AGENT_HEALTH_MONITORING", "PLATFORM", true)));

        ResponseEntity<Map<String, Object>> response = controller.listFlags();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();

        // effectiveMap covers ALL flags — the frontend gates UI on PLATFORM-scope
        // flags it cannot manage, so they MUST be present with their real state.
        Map<String, Boolean> effectiveMap = (Map<String, Boolean>) body.get("effectiveMap");
        assertThat(effectiveMap)
                .containsEntry("DISCOVERY", true)
                .containsEntry("PQC_READINESS", false)
                .containsEntry("AGENT_HEALTH_MONITORING", true);

        // The manageable `flags` list stays ORG-scope only — PLATFORM flags are
        // not actionable at the org level.
        List<com.certmanagement.dto.featureflags.FeatureFlagDto> flags =
                (List<com.certmanagement.dto.featureflags.FeatureFlagDto>) body.get("flags");
        assertThat(flags).extracting("featureKey").containsExactly("DISCOVERY");
    }

    @Test
    @SuppressWarnings("unchecked")
    void listFlags_disabledPlatformFlagSurfacesAsFalse() {
        // Regression guard: a disabled PLATFORM flag must come back as false
        // (not absent), otherwise the client fails open.
        when(featureFlagService.listEffective(100L)).thenReturn(List.of(
                resolved("PQC_READINESS", "PLATFORM", false)));

        ResponseEntity<Map<String, Object>> response = controller.listFlags();

        Map<String, Boolean> effectiveMap =
                (Map<String, Boolean>) response.getBody().get("effectiveMap");
        assertThat(effectiveMap).containsEntry("PQC_READINESS", false);
    }

    @Test
    @SuppressWarnings("unchecked")
    void listFlags_leavesOutFlagsTheOrgCannotControlButKeepsThemOffInEffectiveMap() {
        when(featureFlagService.listEffective(100L)).thenReturn(List.of(
                resolved("DISCOVERY", "ORG", true, false, true),
                resolved("ALERTS", "ORG", false, false, false),
                resolved("IOT_DEVICE_MANAGEMENT", "ORG", true, false, false)));

        Map<String, Object> body = controller.listFlags().getBody();

        List<com.certmanagement.dto.featureflags.FeatureFlagDto> flags =
                (List<com.certmanagement.dto.featureflags.FeatureFlagDto>) body.get("flags");
        assertThat(flags).extracting("featureKey").containsExactly("DISCOVERY");
        assertThat((Map<String, Boolean>) body.get("effectiveMap"))
                .containsEntry("DISCOVERY", false)
                .containsEntry("ALERTS", false)
                .containsEntry("IOT_DEVICE_MANAGEMENT", false);
    }

    @Test
    void featureFlagsPageOff_refusesTheListAndEveryWriteButNotEffective() {
        when(featureFlagService.isEnabled(FeatureFlags.FEATURE_FLAGS_PAGE, 100L)).thenReturn(false);
        when(featureFlagService.effectiveMap(100L)).thenReturn(Map.of(FeatureFlags.FEATURE_FLAGS_PAGE, false));
        com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest update =
                new com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest();
        update.setEnabled(false);
        com.certmanagement.dto.featureflags.FeatureClearRequest clear =
                new com.certmanagement.dto.featureflags.FeatureClearRequest(
                        com.certmanagement.service.lifecycle.BlockerKind.DEPLOYMENT_TARGETS,
                        com.certmanagement.service.lifecycle.ClearAction.CLEAR_TARGETS);

        assertThatThrownBy(() -> controller.listFlags()).isInstanceOf(ManagedByCertpingException.class);
        assertThatThrownBy(() -> controller.updateOrgFlag("DISCOVERY", update))
                .isInstanceOf(ManagedByCertpingException.class);
        assertThatThrownBy(() -> controller.removeOrgFlag("DISCOVERY", null))
                .isInstanceOf(ManagedByCertpingException.class);
        assertThatThrownBy(() -> controller.disableCheck("DISCOVERY"))
                .isInstanceOf(ManagedByCertpingException.class);
        assertThatThrownBy(() -> controller.clear("DISCOVERY", clear))
                .isInstanceOf(ManagedByCertpingException.class)
                .extracting("featureKey").isEqualTo(FeatureFlags.FEATURE_FLAGS_PAGE);

        assertThat(controller.effectiveFlags().getBody().effectiveMap())
                .containsEntry(FeatureFlags.FEATURE_FLAGS_PAGE, false);
        verify(featureFlagService, never()).upsertOrgOverride(any(), any(), anyBoolean(), any());
        verify(featureFlagService, never()).removeOrgOverride(any(), any(), any());
        verifyNoInteractions(lifecycleService);
    }
}
