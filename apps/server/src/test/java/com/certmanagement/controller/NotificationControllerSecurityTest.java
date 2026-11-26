// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.config.MethodSecurityConfig;
import com.certmanagement.constants.Paths;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.CustomPermissionEvaluator;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.ProxyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static com.certmanagement.security.Permissions.ALERTS_VIEW;
import static com.certmanagement.security.Permissions.NOTIFICATIONS_VIEW;
import static com.certmanagement.security.Permissions.ORGANIZATION_MANAGE;
import static com.certmanagement.security.Permissions.ORGANIZATION_VIEW;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The notification list through real method security: a viewer or analyst, who holds
 * notifications:view, is refused; an organization admin gets the list, and never a row's payloadJson.
 */
@SpringJUnitConfig(NotificationControllerSecurityTest.Config.class)
class NotificationControllerSecurityTest {

    private static final String LIST_WITH_PAYLOAD = """
            {"success":true,"data":[{"id":7,"templateName":"reset-password","status":"DELIVERED",
            "payloadJson":"[{\\"templateFields\\":{\\"resetLink\\":\\"https://x/reset-password?token=abc\\"}}]"}],
            "page":0,"size":20,"totalElements":1,"totalPages":1}""";

    @Configuration
    @EnableMethodSecurity
    @Import({MethodSecurityConfig.class, CustomPermissionEvaluator.class})
    static class Config {
        @Bean
        OrganizationRepository organizationRepository() {
            return mock(OrganizationRepository.class);
        }

        @Bean
        UserRepository userRepository() {
            return mock(UserRepository.class);
        }

        @Bean
        PermissionGrantPolicy permissionGrantPolicy(UserRepository users, OrganizationRepository orgs) {
            return new PermissionGrantPolicy(users, orgs, mock(JwtTokenProvider.class));
        }

        @Bean
        ProxyService proxyService() {
            return mock(ProxyService.class);
        }

        @Bean
        NotificationController controller(ProxyService proxyService) {
            return new NotificationController(proxyService);
        }
    }

    @Autowired private NotificationController controller;
    @Autowired private ProxyService proxyService;

    @BeforeEach
    void setUp() {
        reset(proxyService);
        when(proxyService.get(eq(Paths.NOTIFICATIONS_BASE), anyMap())).thenReturn(ResponseEntity.ok(LIST_WITH_PAYLOAD));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    @Test
    void aViewerIsRefused() {
        asMemberOf("ROLE_VIEWER", ORGANIZATION_VIEW, NOTIFICATIONS_VIEW, ALERTS_VIEW);

        assertThatThrownBy(() -> controller.getNotifications(null, null, null, null))
                .isInstanceOf(AccessDeniedException.class);
        verify(proxyService, never()).get(eq(Paths.NOTIFICATIONS_BASE), anyMap());
    }

    @Test
    void aSecurityAnalystIsRefused() {
        asMemberOf("ROLE_SECURITY_ANALYST", ORGANIZATION_VIEW, NOTIFICATIONS_VIEW, ALERTS_VIEW);

        assertThatThrownBy(() -> controller.getNotifications(null, null, null, null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void anOrganizationAdminGetsTheListWithoutPayloads() {
        asMemberOf("ROLE_ORGANIZATION_ADMIN", ORGANIZATION_VIEW, ORGANIZATION_MANAGE, NOTIFICATIONS_VIEW);

        ResponseEntity<String> response = controller.getNotifications(null, null, null, null);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).contains("\"templateName\":\"reset-password\"")
                .doesNotContain("payloadJson").doesNotContain("token=").doesNotContain("resetLink");
    }

    private static void asMemberOf(String... authorities) {
        GatewayRequestContext.set(5, "10", "req", "member@acme.com");
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "user", null, AuthorityUtils.createAuthorityList(authorities)));
    }
}
