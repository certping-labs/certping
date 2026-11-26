// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.config.MethodSecurityConfig;
import com.certmanagement.entity.GlobalSettingsEntity;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.repository.GlobalSettingsRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.CustomPermissionEvaluator;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.GlobalSettingsService;
import com.certmanagement.service.SoftDeletePurgeService;
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

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.certmanagement.security.Permissions.ORGANIZATION_MANAGE;
import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The retention endpoints through real method security and the real retention rules: only a super
 * admin sets an organization's retention, and the purge honours what they set.
 */
@SpringJUnitConfig(DataRetentionControllerSecurityTest.Config.class)
class DataRetentionControllerSecurityTest {

    private static final long ORG_ID = 10L;

    @Configuration
    @EnableMethodSecurity
    @Import({MethodSecurityConfig.class, CustomPermissionEvaluator.class})
    static class Config {
        @Bean
        OrganizationRepository organizationRepository() {
            return mock(OrganizationRepository.class);
        }

        @Bean
        GlobalSettingsRepository globalSettingsRepository() {
            return mock(GlobalSettingsRepository.class);
        }

        @Bean
        SoftDeletePurgeService purgeService() {
            return mock(SoftDeletePurgeService.class);
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
        GlobalSettingsService globalSettingsService(GlobalSettingsRepository settings, OrganizationRepository orgs) {
            return new GlobalSettingsService(settings, orgs, org.mockito.Mockito.mock(com.certmanagement.service.audit.OrganizationAuditRecorder.class));
        }

        @Bean
        DataRetentionController controller(GlobalSettingsService settings, SoftDeletePurgeService purgeService) {
            return new DataRetentionController(settings, purgeService);
        }
    }

    @Autowired private DataRetentionController controller;
    @Autowired private OrganizationRepository organizationRepository;
    @Autowired private GlobalSettingsRepository globalSettingsRepository;
    @Autowired private SoftDeletePurgeService purgeService;
    @Autowired private UserRepository userRepository;

    private Organization organization;

    @BeforeEach
    void setUp() {
        reset(organizationRepository, globalSettingsRepository, purgeService, userRepository);
        organization = Organization.builder().id(ORG_ID).build();
        when(organizationRepository.findById(ORG_ID)).thenReturn(Optional.of(organization));
        when(globalSettingsRepository.findById("soft_delete_retention_days"))
                .thenReturn(Optional.of(GlobalSettingsEntity.builder().value("30").build()));
        when(purgeService.purgeOrganization(anyLong(), anyInt()))
                .thenReturn(new SoftDeletePurgeService.PurgeResult(0, 0, 0, 0, 0, 0, 0, 0));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    @Test
    void aSuperAdminShortensOneOrganizationAndItsPurgeUsesTheShorterPeriod() {
        authenticate("ROLE_SUPER_ADMIN");
        controller.setOrgRetention(ORG_ID, Map.of("days", 7));

        asOrgAdminOf(ORG_ID);
        Map<String, Object> purge = controller.purgeOrganization(ORG_ID).getBody();

        assertThat(organization.getSoftDeleteRetentionDays()).isEqualTo(7);
        assertThat(purge).containsEntry("retentionDays", 7);
        verify(purgeService).purgeOrganization(ORG_ID, 7);
    }

    @Test
    void anOrgAdminCannotWriteTheirOwnRetentionButStillSeesIt() {
        organization.setSoftDeleteRetentionDays(7);
        asOrgAdminOf(ORG_ID);

        assertThatThrownBy(() -> controller.setOrgRetention(ORG_ID, Map.of("days", 90)))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> controller.setOrgRetention(ORG_ID, new java.util.HashMap<>()))
                .isInstanceOf(AccessDeniedException.class);

        assertThat(organization.getSoftDeleteRetentionDays()).isEqualTo(7);
        verify(organizationRepository, never()).save(organization);
        assertThat(controller.getOrgRetention(ORG_ID).getBody())
                .containsEntry("overrideDays", 7)
                .containsEntry("effectiveDays", 7)
                .containsEntry("globalDays", 30);
    }

    private void asOrgAdminOf(long orgId) {
        Role organizationAdmin = Role.builder().id(1L).name(ROLE_ORGANIZATION_ADMIN).isSystemRole(true).build();
        User admin = User.builder().id(5).organization(Organization.builder().id(orgId).build()).active(true)
                .roles(new HashSet<>(Set.of(organizationAdmin))).build();
        when(userRepository.findById(5)).thenReturn(Optional.of(admin));
        GatewayRequestContext.set(5, String.valueOf(orgId), "req", "admin@acme.com");
        authenticate("ROLE_ORGANIZATION_ADMIN", ORGANIZATION_MANAGE);
    }

    private static void authenticate(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "user", null, AuthorityUtils.createAuthorityList(authorities)));
    }
}
