// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.featureflags.FeatureImpactResponse;
import com.certmanagement.exception.FeatureInUseException;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.lifecycle.Blocker;
import com.certmanagement.service.lifecycle.BlockerKind;
import com.certmanagement.service.lifecycle.ClearAction;
import com.certmanagement.service.lifecycle.FeatureImpactService;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.UnsupportedClearException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The clear-first and impact endpoints over HTTP, with the real error envelope. */
class FeatureLifecycleEndpointsTest {

    private static final long ORG_ID = 100L;
    private static final String FEATURE = "DISCOVERY";
    private static final Blocker SCANS = new Blocker(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 3,
            "/discovery", List.of(ClearAction.CANCEL_ALL));

    private final FeatureFlagService featureFlagService = mock(FeatureFlagService.class);
    private final FeatureLifecycleService lifecycleService = mock(FeatureLifecycleService.class);
    private final FeatureImpactService impactService = mock(FeatureImpactService.class);
    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(7, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        when(featureFlagService.isEnabled(com.certmanagement.constants.FeatureFlags.FEATURE_FLAGS_PAGE, ORG_ID))
                .thenReturn(true);
        mvc = MockMvcBuilders.standaloneSetup(
                        new FeatureFlagController(featureFlagService, lifecycleService),
                        new AdminFeatureFlagController(featureFlagService, organizations, impactService))
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build()))
                // Jackson XML is on the classpath; the frontend asks for JSON.
                .defaultRequest(get("/").accept(MediaType.APPLICATION_JSON))
                .build();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void disableCheckListsTheBlockersOfTheCallersOrganization() throws Exception {
        when(lifecycleService.blockersFor(eq(ORG_ID), eq(FEATURE), any())).thenReturn(List.of(SCANS));

        mvc.perform(get("/api/v1/feature-flags/{key}/disable-check", FEATURE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.featureKey").value(FEATURE))
                .andExpect(jsonPath("$.canDisable").value(false))
                .andExpect(jsonPath("$.blockers[0].kind").value("RUNNING_DISCOVERY_SCANS"))
                .andExpect(jsonPath("$.blockers[0].label").value("Running discovery scans"))
                .andExpect(jsonPath("$.blockers[0].count").value(3))
                .andExpect(jsonPath("$.blockers[0].href").value("/discovery"))
                .andExpect(jsonPath("$.blockers[0].actions[0]").value("CANCEL_ALL"));
    }

    @Test
    void aClearFeatureCanBeDisabled() throws Exception {
        when(lifecycleService.blockersFor(eq(ORG_ID), eq(FEATURE), any())).thenReturn(List.of());

        mvc.perform(get("/api/v1/feature-flags/{key}/disable-check", FEATURE))
                .andExpect(jsonPath("$.canDisable").value(true))
                .andExpect(jsonPath("$.blockers").isEmpty());
    }

    @Test
    void theFeatureFlagsPageOffIs403ManagedByCertpingNamingThePage() throws Exception {
        when(featureFlagService.isEnabled(com.certmanagement.constants.FeatureFlags.FEATURE_FLAGS_PAGE, ORG_ID))
                .thenReturn(false);

        mvc.perform(get("/api/v1/feature-flags"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("MANAGED_BY_CERTPING"))
                .andExpect(jsonPath("$.featureKey").value("FEATURE_FLAGS_PAGE"))
                .andExpect(jsonPath("$.message").value("Feature flags aren't available. Ask your CertPing administrator."));
        mvc.perform(put("/api/v1/feature-flags/{key}", FEATURE).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isForbidden());
        verify(featureFlagService, never()).upsertOrgOverride(anyLong(), anyString(), anyBoolean(), any());
    }

    @Test
    void anOrgAdminsWriteToAFlagManagedByCertpingIs403() throws Exception {
        when(featureFlagService.upsertOrgOverride(eq(ORG_ID), eq("CERTIFICATE_RENEWAL"), eq(false), any()))
                .thenThrow(new com.certmanagement.exception.ManagedByCertpingException("CERTIFICATE_RENEWAL", "managed"));

        mvc.perform(put("/api/v1/feature-flags/{key}", "CERTIFICATE_RENEWAL").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("MANAGED_BY_CERTPING"))
                .andExpect(jsonPath("$.featureKey").value("CERTIFICATE_RENEWAL"));
    }

    @Test
    void anUnknownFeatureIsNotFound() throws Exception {
        when(featureFlagService.getGlobal("NOPE")).thenThrow(new ResourceNotFoundException("Feature flag not found"));

        mvc.perform(get("/api/v1/feature-flags/NOPE/disable-check")).andExpect(status().isNotFound());
        mvc.perform(post("/api/v1/feature-flags/NOPE/clear").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"kind\":\"RUNNING_DISCOVERY_SCANS\",\"action\":\"CANCEL_ALL\"}"))
                .andExpect(status().isNotFound());
        verify(lifecycleService, never()).clear(anyLong(), anyString(), any(), any(), any());
    }

    @Test
    void switchingOffWhileInUseIs409FeatureInUseWithTheBlockers() throws Exception {
        when(featureFlagService.upsertOrgOverride(eq(ORG_ID), eq(FEATURE), eq(false), any()))
                .thenThrow(new FeatureInUseException(FEATURE, List.of(SCANS)));

        mvc.perform(put("/api/v1/feature-flags/{key}", FEATURE).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("FEATURE_IN_USE"))
                .andExpect(jsonPath("$.featureKey").value(FEATURE))
                .andExpect(jsonPath("$.blockers[0].kind").value("RUNNING_DISCOVERY_SCANS"))
                .andExpect(jsonPath("$.blockers[0].count").value(3))
                .andExpect(jsonPath("$.blockers[0].actions[0]").value("CANCEL_ALL"));
    }

    @Test
    void clearReturnsWhatItChanged() throws Exception {
        when(lifecycleService.clear(eq(ORG_ID), eq(FEATURE), eq(BlockerKind.RUNNING_DISCOVERY_SCANS), eq(ClearAction.CANCEL_ALL),
                any()))
                .thenReturn(3);

        mvc.perform(post("/api/v1/feature-flags/{key}/clear", FEATURE).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"kind\":\"RUNNING_DISCOVERY_SCANS\",\"action\":\"CANCEL_ALL\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kind").value("RUNNING_DISCOVERY_SCANS"))
                .andExpect(jsonPath("$.action").value("CANCEL_ALL"))
                .andExpect(jsonPath("$.affected").value(3));
    }

    @Test
    void aLinkOnlyKindCannotBeClearedInBulk() throws Exception {
        when(lifecycleService.clear(eq(ORG_ID), eq("INTEGRATIONS"), eq(BlockerKind.ACTIVE_INTEGRATIONS),
                eq(ClearAction.DELETE_ALL), any())).thenThrow(new UnsupportedClearException("INTEGRATIONS",
                BlockerKind.ACTIVE_INTEGRATIONS, ClearAction.DELETE_ALL));

        mvc.perform(post("/api/v1/feature-flags/INTEGRATIONS/clear").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"kind\":\"ACTIVE_INTEGRATIONS\",\"action\":\"DELETE_ALL\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void aClearRequestWithoutAnActionIsRejected() throws Exception {
        mvc.perform(post("/api/v1/feature-flags/{key}/clear", FEATURE).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"kind\":\"RUNNING_DISCOVERY_SCANS\"}"))
                .andExpect(status().isBadRequest());
        verify(lifecycleService, never()).clear(anyLong(), anyString(), any(), any(), any());
        verify(featureFlagService, never()).upsertOrgOverride(anyLong(), anyString(), anyBoolean(), any());
    }

    @Test
    void impactIsScopedToOneOrganizationOrOneOrgType() throws Exception {
        when(impactService.impact(FEATURE, ImpactScope.orgType("B2B"))).thenReturn(new FeatureImpactResponse(
                FEATURE, 212, List.of(new FeatureImpactResponse.Item(BlockerKind.RUNNING_DISCOVERY_SCANS,
                "Running discovery scans", 1840)), true, List.of()));

        mvc.perform(get("/api/v1/admin/feature-flags/{key}/impact", FEATURE).param("orgType", "B2B"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.organizationsAffected").value(212))
                .andExpect(jsonPath("$.items[0].count").value(1840))
                .andExpect(jsonPath("$.notifiesAdmins").value(true));
        when(organizations.existsLiveById(5L)).thenReturn(true);
        mvc.perform(get("/api/v1/admin/feature-flags/{key}/impact", FEATURE).param("organizationId", "5"))
                .andExpect(status().isOk());
        verify(impactService).impact(FEATURE, ImpactScope.organization(5L));
    }

    @Test
    void impactForAnUnknownOrDeletedOrganizationIsNotFound() throws Exception {
        when(organizations.existsLiveById(404L)).thenReturn(false);

        mvc.perform(get("/api/v1/admin/feature-flags/{key}/impact", FEATURE).param("organizationId", "404"))
                .andExpect(status().isNotFound());
        verify(impactService, never()).impact(anyString(), any());
    }

    @Test
    void impactRefusesBothFiltersAndAnUnknownOrgType() throws Exception {
        mvc.perform(get("/api/v1/admin/feature-flags/{key}/impact", FEATURE)
                        .param("organizationId", "5").param("orgType", "B2B"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/admin/feature-flags/{key}/impact", FEATURE).param("orgType", "UNKNOWN_TYPE"))
                .andExpect(status().isBadRequest());
        verify(impactService, never()).impact(anyString(), any());
    }
}
