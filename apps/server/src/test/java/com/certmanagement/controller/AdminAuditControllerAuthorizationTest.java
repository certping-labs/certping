// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditTrailExporter;
import com.certmanagement.audit.AuditTrailReader;
import com.certmanagement.audit.AuditVisibilityPolicy;
import com.certmanagement.audit.AuditedReads;
import com.certmanagement.config.MethodSecurityConfig;
import com.certmanagement.dto.audit.AuditTrailPage;
import com.certmanagement.security.CustomPermissionEvaluator;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The platform audit routes through real method security: a super admin holding {@code audit:view} is served;
 * an organization admin holding {@code audit:view}, and a super admin without it, are refused before anything
 * is read.
 */
@SpringJUnitConfig(AdminAuditControllerAuthorizationTest.Config.class)
class AdminAuditControllerAuthorizationTest {

    @Configuration
    @EnableMethodSecurity
    @Import({MethodSecurityConfig.class, CustomPermissionEvaluator.class})
    static class Config {
        @Bean AuditTrailReader reader() { return mock(AuditTrailReader.class); }
        @Bean AuditTrailExporter exporter() { return mock(AuditTrailExporter.class); }
        @Bean AuditedReads reads() { return mock(AuditedReads.class); }
        @Bean AuditVisibilityPolicy policy() { return new AuditVisibilityPolicy(mock(FeatureFlagService.class)); }

        @Bean
        AdminAuditController controller(AuditTrailReader reader, AuditTrailExporter exporter,
                                        AuditVisibilityPolicy policy, AuditedReads reads) {
            return new AdminAuditController(reader, exporter, policy, reads);
        }
    }

    @Autowired private AdminAuditController controller;
    @Autowired private AuditTrailReader reader;
    @Autowired private AuditTrailExporter exporter;
    @Autowired private AuditedReads reads;

    /** Every route, called as the controller method. */
    static Stream<Consumer<AdminAuditController>> routes() {
        return Stream.of(
                c -> c.queryPlatformAuditLogs(new com.certmanagement.dto.audit.AuditPlatformFilterRequest(), null, null),
                c -> c.exportPlatformAuditLogs(new com.certmanagement.dto.audit.AuditPlatformFilterRequest(), "csv"),
                c -> c.getPlatformCategories(null),
                c -> c.getPlatformActions(),
                c -> c.getPlatformResources());
    }

    @BeforeEach
    void setUp() {
        reset(reader, exporter, reads);
        when(reader.readPlatform(any(), any(), any())).thenReturn(new AuditTrailPage<>(List.of(), 0, 20, 0, 0, true,
                true, 0, true, false, null, null));
        when(exporter.exportPlatform(any(), any(), any())).thenReturn(new AuditTrailExporter.AuditExport("x.csv",
                MediaType.TEXT_PLAIN, out -> { }, 0));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void theCasesCoverEveryRoute() {
        long mapped = Arrays.stream(AdminAuditController.class.getDeclaredMethods())
                .filter(m -> AnnotatedElementUtils.hasAnnotation(m, GetMapping.class)).count();
        assertThat(routes()).hasSize((int) mapped);
    }

    @ParameterizedTest
    @MethodSource("routes")
    void anOrganizationAdminWithAuditViewIsRefused(Consumer<AdminAuditController> route) {
        authenticate("ROLE_ORGANIZATION_ADMIN", "audit:view");

        assertThatThrownBy(() -> route.accept(controller)).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(reader, exporter, reads);
    }

    @ParameterizedTest
    @MethodSource("routes")
    void aSuperAdminWithoutAuditViewIsRefused(Consumer<AdminAuditController> route) {
        authenticate("ROLE_SUPER_ADMIN");

        assertThatThrownBy(() -> route.accept(controller)).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(reader, exporter, reads);
    }

    @ParameterizedTest
    @MethodSource("routes")
    void aSuperAdminWithAuditViewIsServed(Consumer<AdminAuditController> route) {
        authenticate("ROLE_SUPER_ADMIN", "audit:view");

        route.accept(controller);
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "caller", "n/a", Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList()));
    }
}
