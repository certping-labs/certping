// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.config.MethodSecurityConfig;
import com.certmanagement.dto.notification.NotificationSettingsRequest;
import com.certmanagement.dto.notification.NotificationSettingsResponse;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.CustomPermissionEvaluator;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.notification.NotificationCategory;
import com.certmanagement.service.notification.NotificationPreferenceService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.certmanagement.security.Permissions.ORGANIZATION_MANAGE;
import static com.certmanagement.security.Permissions.ORGANIZATION_VIEW;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The notification settings endpoints through real method security: only the organization's own
 * admins read and change them, and a super admin may read them but never change what a customer
 * receives.
 */
@SpringJUnitConfig(NotificationSettingsControllerSecurityTest.Config.class)
class NotificationSettingsControllerSecurityTest {

    private static final long ORG_ID = 10L;
    private static final long OTHER_ORG_ID = 11L;

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
        NotificationPreferenceService preferences() {
            return mock(NotificationPreferenceService.class);
        }

        @Bean
        NotificationSettingsController controller(NotificationPreferenceService preferences) {
            return new NotificationSettingsController(preferences);
        }
    }

    @Autowired private NotificationSettingsController controller;
    @Autowired private NotificationPreferenceService preferences;

    @BeforeEach
    void setUp() {
        reset(preferences);
        when(preferences.muted(anyLong())).thenReturn(EnumSet.of(NotificationCategory.REPORTS));
        when(preferences.replaceMuted(anyLong(), anyCollection()))
                .thenReturn(EnumSet.of(NotificationCategory.CERTIFICATE_ACTIVITY));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    @Test
    void anOrganizationAdminReadsAndChangesTheirOwnSettings() {
        asMemberOf(ORG_ID, "ROLE_ORGANIZATION_ADMIN", ORGANIZATION_MANAGE);

        NotificationSettingsResponse read = controller.getNotificationSettings(ORG_ID).getBody();
        NotificationSettingsResponse saved = controller.setNotificationSettings(ORG_ID,
                new NotificationSettingsRequest(List.of("CERTIFICATE_ACTIVITY"))).getBody();

        assertThat(read.categories()).extracting(c -> c.key() + ":" + c.enabled()).containsExactly(
                "CERTIFICATE_ACTIVITY:true", "REPORTS:false");
        assertThat(saved.categories()).extracting(c -> c.key() + ":" + c.enabled()).containsExactly(
                "CERTIFICATE_ACTIVITY:false", "REPORTS:true");
        verify(preferences).replaceMuted(ORG_ID, List.of("CERTIFICATE_ACTIVITY"));
    }

    @Test
    void aMemberWithoutOrganizationManageCanNeitherReadNorChange() {
        asMemberOf(ORG_ID, "ROLE_VIEWER", ORGANIZATION_VIEW, "notifications:view");

        assertThatThrownBy(() -> controller.getNotificationSettings(ORG_ID)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> controller.setNotificationSettings(ORG_ID, new NotificationSettingsRequest(List.of())))
                .isInstanceOf(AccessDeniedException.class);
        verify(preferences, never()).replaceMuted(anyLong(), anyCollection());
    }

    @Test
    void anotherOrganizationsAdminCanNeitherReadNorChange() {
        asMemberOf(OTHER_ORG_ID, "ROLE_ORGANIZATION_ADMIN", ORGANIZATION_MANAGE);

        assertThatThrownBy(() -> controller.getNotificationSettings(ORG_ID)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> controller.setNotificationSettings(ORG_ID, new NotificationSettingsRequest(List.of())))
                .isInstanceOf(AccessDeniedException.class);
        verify(preferences, never()).muted(anyLong());
    }

    @Test
    void aSuperAdminReadsForSupportButNeverChangesWhatACustomerReceives() {
        authenticate("ROLE_SUPER_ADMIN", ORGANIZATION_MANAGE);

        assertThat(controller.getNotificationSettings(ORG_ID).getBody()).isNotNull();
        assertThatThrownBy(() -> controller.setNotificationSettings(ORG_ID,
                new NotificationSettingsRequest(List.of("REPORTS")))).isInstanceOf(AccessDeniedException.class);
        verify(preferences, never()).replaceMuted(anyLong(), anyCollection());
    }

    private static void asMemberOf(long orgId, String... authorities) {
        GatewayRequestContext.set(5, String.valueOf(orgId), "req", "admin@acme.com");
        authenticate(authorities);
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "user", null, AuthorityUtils.createAuthorityList(Set.of(authorities).toArray(String[]::new))));
    }
}
