// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.featureflags.BaselinePreviewResponse;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse.CausePreview;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse.FeaturePreview;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse.ItemCount;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.service.lifecycle.BaselinePreviewService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Real method security around the baseline preview: super admin only, read-only JSON. */
class AdminFeatureLifecycleControllerTest {

    private static final String PREVIEW = "/api/v1/admin/feature-lifecycle/baseline-preview";

    private AnnotationConfigApplicationContext context;
    private BaselinePreviewService previewService;
    private MockMvc mvc;

    @Configuration
    @EnableMethodSecurity
    static class Wiring {
        @Bean BaselinePreviewService baselinePreviewService() { return mock(BaselinePreviewService.class); }
        @Bean AdminFeatureLifecycleController controller(BaselinePreviewService service) {
            return new AdminFeatureLifecycleController(service);
        }
    }

    @BeforeEach
    void setUp() {
        context = new AnnotationConfigApplicationContext(Wiring.class);
        previewService = context.getBean(BaselinePreviewService.class);
        mvc = MockMvcBuilders.standaloneSetup(context.getBean(AdminFeatureLifecycleController.class))
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build()))
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        context.close();
    }

    @Test
    void anOrgAdminWithEveryFlagPermissionIsRefused() throws Exception {
        authenticate("ROLE_ORGANIZATION_ADMIN", "feature_flags:administer", "feature_flags:manage");

        mvc.perform(get(PREVIEW)).andExpect(status().isForbidden());

        verifyNoInteractions(previewService);
    }

    @Test
    void aSuperAdminSeesWhatTheBaselineWouldPauseByCause() throws Exception {
        authenticate("ROLE_SUPER_ADMIN");
        when(previewService.preview()).thenReturn(new BaselinePreviewResponse(List.of(new FeaturePreview(
                "DISCOVERY", 2, 5, List.of(new CausePreview("ORG_TYPE", 2, 5,
                        List.of(new ItemCount("RUNNING_DISCOVERY_SCANS", "Running discovery scans", 5))))))));

        mvc.perform(get(PREVIEW).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.features[0].featureKey").value("DISCOVERY"))
                .andExpect(jsonPath("$.features[0].organizations").value(2))
                .andExpect(jsonPath("$.features[0].byCause[0].cause").value("ORG_TYPE"))
                .andExpect(jsonPath("$.features[0].byCause[0].items[0].count").value(5));
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "caller", "n/a", Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList()));
    }
}
