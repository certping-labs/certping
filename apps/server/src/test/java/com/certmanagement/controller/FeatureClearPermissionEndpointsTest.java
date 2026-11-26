// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.Permissions;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.lifecycle.Blocker;
import com.certmanagement.service.lifecycle.BlockerKind;
import com.certmanagement.service.lifecycle.ClearAction;
import com.certmanagement.service.lifecycle.FeatureLifecycle;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import com.certmanagement.service.lifecycle.FeatureLifecycleRegistry;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code POST …/clear} and {@code GET …/disable-check} over HTTP with the real
 * {@link FeatureLifecycleService}: {@code feature_flags:manage} lets an admin open the dialog, but each
 * bulk action also needs the permission the same change needs one record at a time.
 */
class FeatureClearPermissionEndpointsTest {

    private static final long ORG_ID = 100L;

    private final FeatureFlagService featureFlagService = mock(FeatureFlagService.class);
    private final FeatureLifecycleRegistry registry = mock(FeatureLifecycleRegistry.class);
    private final FeatureLifecycleLock lock = mock(FeatureLifecycleLock.class);
    private final FeatureFlagChangeAudit changeAudit = mock(FeatureFlagChangeAudit.class);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(7, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        when(featureFlagService.isEnabled(FeatureFlags.FEATURE_FLAGS_PAGE, ORG_ID)).thenReturn(true);
        FeatureLifecycleService lifecycleService = new FeatureLifecycleService(registry, lock, changeAudit);
        mvc = MockMvcBuilders.standaloneSetup(new FeatureFlagController(featureFlagService, lifecycleService))
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build()))
                .defaultRequest(get("/").accept(MediaType.APPLICATION_JSON))
                .build();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    /** Every bulk action, with the permission the same change needs one record at a time. */
    static Stream<Arguments> bulkActions() {
        return Stream.of(
                Arguments.of(FeatureFlags.CERTIFICATE_DEPLOYMENT, BlockerKind.DEPLOYMENT_TARGETS,
                        ClearAction.CLEAR_TARGETS, Permissions.CERTIFICATE_ISSUE),
                Arguments.of(FeatureFlags.CERTIFICATE_RENEWAL, BlockerKind.AUTO_RENEW_CERTS,
                        ClearAction.DISABLE_AUTO_RENEW, Permissions.CERTIFICATE_RENEW),
                Arguments.of(FeatureFlags.CA_LETS_ENCRYPT, BlockerKind.AUTO_RENEW_CERTS_ON_CA,
                        ClearAction.DISABLE_AUTO_RENEW, Permissions.CERTIFICATE_RENEW),
                Arguments.of(FeatureFlags.DISCOVERY, BlockerKind.RUNNING_DISCOVERY_SCANS,
                        ClearAction.CANCEL_ALL, Permissions.CERTIFICATE_DEPLOY));
    }

    @ParameterizedTest(name = "{2} on {1} without {3} is 403")
    @MethodSource("bulkActions")
    void featureFlagsManageAloneIsForbidden(String featureKey, BlockerKind kind, ClearAction action,
                                            String permission) throws Exception {
        FeatureLifecycle lifecycle = lifecycleOffering(featureKey, kind, action);
        callerHolds(Permissions.FEATURE_FLAGS_MANAGE);

        clear(featureKey, kind, action).andExpect(status().isForbidden());

        verify(lifecycle, never()).clear(anyLong(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
        verify(lock, never()).lock(anyLong(), anyString());
        verify(changeAudit, never()).recordClear(anyLong(), anyString(), anyString(), anyString(), anyInt());
    }

    @ParameterizedTest(name = "{2} on {1} with {3} is 200")
    @MethodSource("bulkActions")
    void theRecordPermissionAllowsTheBulkAction(String featureKey, BlockerKind kind, ClearAction action,
                                                String permission) throws Exception {
        FeatureLifecycle lifecycle = lifecycleOffering(featureKey, kind, action);
        when(lifecycle.clear(ORG_ID, kind, action)).thenReturn(4);
        callerHolds(Permissions.FEATURE_FLAGS_MANAGE, permission);

        clear(featureKey, kind, action)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.affected").value(4));

        verify(lock).lock(ORG_ID, featureKey);
        verify(changeAudit).recordClear(ORG_ID, featureKey, kind.name(), action.name(), 4);
    }

    @Test
    void disableCheckOffersOnlyTheActionsTheCallerMayPerform() throws Exception {
        FeatureLifecycle lifecycle = mock(FeatureLifecycle.class);
        when(registry.find(FeatureFlags.CERTIFICATE_DEPLOYMENT)).thenReturn(Optional.of(lifecycle));
        when(lifecycle.blockers(ORG_ID)).thenReturn(List.of(new Blocker(BlockerKind.DEPLOYMENT_TARGETS,
                "Deployment targets", 3, "/cert-manager/deployments",
                List.of(ClearAction.CLEAR_TARGETS))));

        callerHolds(Permissions.FEATURE_FLAGS_MANAGE);
        mvc.perform(get("/api/v1/feature-flags/{key}/disable-check", FeatureFlags.CERTIFICATE_DEPLOYMENT))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canDisable").value(false))
                .andExpect(jsonPath("$.blockers[0].kind").value("DEPLOYMENT_TARGETS"))
                .andExpect(jsonPath("$.blockers[0].count").value(3))
                .andExpect(jsonPath("$.blockers[0].href").value("/cert-manager/deployments"))
                .andExpect(jsonPath("$.blockers[0].actions").isEmpty());

        callerHolds(Permissions.FEATURE_FLAGS_MANAGE, Permissions.CERTIFICATE_ISSUE);
        mvc.perform(get("/api/v1/feature-flags/{key}/disable-check", FeatureFlags.CERTIFICATE_DEPLOYMENT))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.blockers[0].actions[0]").value("CLEAR_TARGETS"));
    }

    private FeatureLifecycle lifecycleOffering(String featureKey, BlockerKind kind, ClearAction action) {
        FeatureLifecycle lifecycle = mock(FeatureLifecycle.class);
        when(registry.find(featureKey)).thenReturn(Optional.of(lifecycle));
        lenient().when(lifecycle.featureKey()).thenReturn(featureKey);
        when(lifecycle.kinds()).thenReturn(List.of(kind));
        when(lifecycle.supportedActions(kind)).thenReturn(Set.of(action));
        return lifecycle;
    }

    private org.springframework.test.web.servlet.ResultActions clear(String featureKey, BlockerKind kind,
                                                                     ClearAction action) throws Exception {
        return mvc.perform(post("/api/v1/feature-flags/{key}/clear", featureKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"kind\":\"" + kind + "\",\"action\":\"" + action + "\"}"));
    }

    private static void callerHolds(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("admin", null, authorities));
    }
}
