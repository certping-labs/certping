// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/v1/feature-flags/effective} behind real method security: any signed-in member of
 * an organization reads it without {@code feature_flags:view}; without an organization the map is
 * empty; an anonymous caller is refused.
 */
class EffectiveFeatureFlagsEndpointTest {

    private static final String PATH = "/api/v1/feature-flags/effective";
    private static final long ORG_ID = 42L;

    private AnnotationConfigApplicationContext context;
    private FeatureFlagService featureFlagService;
    private MockMvc mvc;

    @Configuration
    @EnableMethodSecurity
    static class Wiring {
        @Bean FeatureFlagService featureFlagService() { return mock(FeatureFlagService.class); }
        @Bean FeatureLifecycleService lifecycleService() { return mock(FeatureLifecycleService.class); }
        @Bean FeatureFlagController controller(FeatureFlagService flags, FeatureLifecycleService lifecycle) {
            return new FeatureFlagController(flags, lifecycle);
        }
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        featureFlagService = context.getBean(FeatureFlagService.class);
        mvc = MockMvcBuilders.standaloneSetup(context.getBean(FeatureFlagController.class))
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build()))
                .defaultRequest(get("/").accept(MediaType.APPLICATION_JSON))
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
        context.close();
    }

    @Test
    void aMemberWithoutFeatureFlagViewGetsTheOrganizationsEffectiveMap() throws Exception {
        authenticate("ROLE_VIEWER", "certificate:read");
        GatewayRequestContext.set(9, String.valueOf(ORG_ID), "req-1", "member@example.com");
        Map<String, Boolean> effective = new TreeMap<>(Map.of("DISCOVERY", true, "PQC_READINESS", false));
        when(featureFlagService.effectiveMap(ORG_ID)).thenReturn(effective);

        mvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"effectiveMap\":{\"DISCOVERY\":true,\"PQC_READINESS\":false}}", true));
    }

    @Test
    void aCallerWithoutAnOrganizationGetsAnEmptyMap() throws Exception {
        authenticate("ROLE_SUPER_ADMIN", "feature_flags:view");
        GatewayRequestContext.set(1, null, "req-2", "root@example.com");

        mvc.perform(get(PATH))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"effectiveMap\":{}}", true));
        verify(featureFlagService, never()).effectiveMap(anyLong());
    }

    @Test
    void anAnonymousCallerIsRefused() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        GatewayRequestContext.set(null, String.valueOf(ORG_ID), "req-3", null);

        mvc.perform(get(PATH)).andExpect(status().is4xxClientError());
        verify(featureFlagService, never()).effectiveMap(anyLong());
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "caller", "n/a", Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList()));
    }
}
