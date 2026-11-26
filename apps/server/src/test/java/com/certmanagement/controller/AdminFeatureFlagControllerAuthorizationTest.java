// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Real method security around the real controller: an org admin who carries
 * {@code feature_flags:administer} in the token (as org admins once did) is refused on
 * every endpoint, and a super admin is served.
 */
class AdminFeatureFlagControllerAuthorizationTest {

    private static final String FLAG = "AUDIT_LOGS";
    private static final long ORG_ID = 7L;
    private static final String ENABLE = "{\"enabled\":true}";

    private AnnotationConfigApplicationContext context;
    private FeatureFlagService featureFlagService;
    private MockMvc mvc;

    @Configuration
    @EnableMethodSecurity
    static class Wiring {
        @Bean FeatureFlagService featureFlagService() { return mock(FeatureFlagService.class); }
        @Bean OrganizationRepository organizationRepository() { return mock(OrganizationRepository.class); }
        @Bean AdminFeatureFlagController controller(FeatureFlagService service, OrganizationRepository orgs) {
            return new AdminFeatureFlagController(service, orgs, org.mockito.Mockito.mock(com.certmanagement.service.lifecycle.FeatureImpactService.class));
        }
    }

    record Call(HttpMethod method, String uri, String body) {
        @Override
        public String toString() {
            return method + " " + uri;
        }
    }

    static Stream<Call> endpoints() {
        String base = "/api/v1/admin/feature-flags";
        return Stream.of(
                new Call(HttpMethod.GET, base + "/org/" + ORG_ID, null),
                new Call(HttpMethod.GET, base + "/summary", null),
                new Call(HttpMethod.GET, base + "/org-type/B2B", null),
                new Call(HttpMethod.GET, base, null),
                new Call(HttpMethod.PUT, base + "/" + FLAG, ENABLE),
                new Call(HttpMethod.PUT, base + "/org-type/B2B/bulk", ENABLE),
                new Call(HttpMethod.PUT, base + "/" + FLAG + "/org-type/B2B", ENABLE),
                new Call(HttpMethod.DELETE, base + "/" + FLAG + "/org-type/B2B", null),
                new Call(HttpMethod.PUT, base + "/" + FLAG + "/overrides/" + ORG_ID, ENABLE),
                new Call(HttpMethod.GET, base + "/" + FLAG + "/overrides", null),
                new Call(HttpMethod.GET, base + "/" + FLAG + "/impact", null),
                new Call(HttpMethod.DELETE, base + "/" + FLAG + "/overrides/" + ORG_ID, null));
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        featureFlagService = context.getBean(FeatureFlagService.class);
        mvc = MockMvcBuilders.standaloneSetup(context.getBean(AdminFeatureFlagController.class))
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build()))
                .setCustomArgumentResolvers(new PageableHandlerMethodArgumentResolver())
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        context.close();
    }

    @Test
    void theCasesCoverEveryEndpoint() {
        long mapped = Arrays.stream(AdminFeatureFlagController.class.getDeclaredMethods())
                .filter(m -> AnnotatedElementUtils.hasAnnotation(m, RequestMapping.class))
                .count();
        assertThat(endpoints()).hasSize((int) mapped);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("endpoints")
    void orgAdminIsRefusedEvenWithTheAdministerPermission(Call call) throws Exception {
        authenticate("ROLE_ORGANIZATION_ADMIN", "feature_flags:administer", "feature_flags:manage",
                "feature_flags:view");

        perform(call).andExpect(status().isForbidden());

        verifyNoInteractions(featureFlagService);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("endpoints")
    void superAdminIsServed(Call call) throws Exception {
        authenticate("ROLE_SUPER_ADMIN", "feature_flags:view", "feature_flags:manage", "feature_flags:administer");
        OrganizationFeatureFlag saved = OrganizationFeatureFlag.builder().featureKey(FLAG).build();
        when(featureFlagService.upsertOrgOverrideAsAdmin(anyLong(), anyString(), anyBoolean(), any())).thenReturn(saved);
        GlobalFeatureFlag global = GlobalFeatureFlag.builder().featureKey(FLAG).scope("ORG").enabled(true).build();
        when(featureFlagService.listEffective(ORG_ID)).thenReturn(List.of(
                new FeatureFlagService.ResolvedFlag(global, true, null, "B2B", true, false, true)));

        perform(call).andExpect(status().isOk());
    }

    private ResultActions perform(Call call) throws Exception {
        var builder = request(call.method(), call.uri());
        if (call.body() != null) {
            builder.contentType(MediaType.APPLICATION_JSON).content(call.body());
        }
        return mvc.perform(builder);
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "caller", "n/a", Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList()));
    }
}
