// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.config.MethodSecurityConfig;
import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.dto.organization.UpdateOrganizationRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.CustomPermissionEvaluator;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.service.GlobalSettingsService;
import com.certmanagement.service.OrganizationService;
import com.certmanagement.service.SoftDeletePurgeService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.certmanagement.security.Permissions.ORGANIZATION_MANAGE;
import static com.certmanagement.security.Permissions.ORGANIZATION_VIEW;
import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Changing, suspending, deleting or purging an organization, through real method security and the
 * real {@link PermissionGrantPolicy}: a super admin or that organization's admin, with the role in
 * the token and in the database, and no one who merely holds {@code organization:manage}.
 */
@SpringJUnitConfig(OrganizationAdministrationAuthorizationTest.Config.class)
class OrganizationAdministrationAuthorizationTest {

    private static final long ORG_ID = 10L;
    private static final long OTHER_ORG_ID = 20L;
    private static final int CALLER_ID = 5;

    @Configuration
    @EnableMethodSecurity
    @Import({MethodSecurityConfig.class, CustomPermissionEvaluator.class})
    static class Config {
        @Bean UserRepository userRepository() { return mock(UserRepository.class); }
        @Bean OrganizationRepository organizationRepository() { return mock(OrganizationRepository.class); }
        @Bean JwtTokenProvider jwtTokenProvider() { return mock(JwtTokenProvider.class); }
        @Bean OrganizationService organizationService() { return mock(OrganizationService.class); }
        @Bean GlobalSettingsService globalSettingsService() { return mock(GlobalSettingsService.class); }
        @Bean SoftDeletePurgeService purgeService() { return mock(SoftDeletePurgeService.class); }

        @Bean
        PermissionGrantPolicy permissionGrantPolicy(UserRepository users, OrganizationRepository organizations,
                                                    JwtTokenProvider jwtTokenProvider) {
            return new PermissionGrantPolicy(users, organizations, jwtTokenProvider);
        }

        @Bean
        OrganizationController organizationController(OrganizationService organizationService) {
            return new OrganizationController(organizationService);
        }

        @Bean
        DataRetentionController dataRetentionController(GlobalSettingsService settings, SoftDeletePurgeService purge) {
            return new DataRetentionController(settings, purge);
        }
    }

    @Autowired private OrganizationController organizationController;
    @Autowired private DataRetentionController dataRetentionController;
    @Autowired private UserRepository userRepository;
    @Autowired private JwtTokenProvider jwtTokenProvider;
    @Autowired private OrganizationService organizationService;
    @Autowired private SoftDeletePurgeService purgeService;
    @Autowired private GlobalSettingsService globalSettingsService;

    @BeforeEach
    void setUp() {
        reset(userRepository, jwtTokenProvider, organizationService, purgeService, globalSettingsService);
        when(jwtTokenProvider.effectivePermissions(any(User.class), any()))
                .thenAnswer(i -> ((User) i.getArgument(0)).getEffectivePermissionNames());
        when(purgeService.purgeOrganization(anyLong(), anyInt()))
                .thenReturn(new SoftDeletePurgeService.PurgeResult(0, 0, 0, 0, 0, 0, 0, 0));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    private Map<String, Executable> organizationWrites(long organizationId) {
        Map<String, Executable> writes = new LinkedHashMap<>();
        writes.put("suspend", () -> organizationController.updateOrganization(String.valueOf(organizationId),
                UpdateOrganizationRequest.builder().active(false).build()));
        writes.put("rename", () -> organizationController.updateOrganization(String.valueOf(organizationId),
                UpdateOrganizationRequest.builder().name("Renamed").build()));
        writes.put("delete", () -> organizationController.deleteOrganization(String.valueOf(organizationId)));
        writes.put("purge", () -> dataRetentionController.purgeOrganization(organizationId));
        return writes;
    }

    @Test
    void aSuperAdminMayChangeAnyOrganization() {
        signIn(null, List.of(ROLE_SUPER_ADMIN), ORGANIZATION_MANAGE);

        organizationWrites(OTHER_ORG_ID).forEach((name, write) ->
                assertThatCode(write::execute).as(name).doesNotThrowAnyException());
    }

    @Test
    void anOrganizationAdminMayChangeTheirOwnOrganization() {
        signIn(ORG_ID, List.of(ROLE_ORGANIZATION_ADMIN), ORGANIZATION_MANAGE, ORGANIZATION_VIEW);

        organizationWrites(ORG_ID).forEach((name, write) ->
                assertThatCode(write::execute).as(name).doesNotThrowAnyException());
    }

    @Test
    void aMemberWhoWasGivenOrganizationManageMayNot() {
        signIn(ORG_ID, List.of("OPS"), ORGANIZATION_MANAGE, ORGANIZATION_VIEW);

        assertAllRefused(ORG_ID);
    }

    @Test
    void anOrganizationAdminTokenWithoutTheRoleInTheDatabaseMayNot() {
        signIn(ORG_ID, List.of(ROLE_ORGANIZATION_ADMIN), ORGANIZATION_MANAGE);
        demoteInDatabase();

        assertAllRefused(ORG_ID);
    }

    @Test
    void anOrganizationAdminMayNotChangeAnotherOrganization() {
        signIn(ORG_ID, List.of(ROLE_ORGANIZATION_ADMIN), ORGANIZATION_MANAGE);

        assertAllRefused(OTHER_ORG_ID);
    }

    @Test
    void anOrganizationAdminKeepsTheReads() {
        signIn(ORG_ID, List.of(ROLE_ORGANIZATION_ADMIN), ORGANIZATION_MANAGE, ORGANIZATION_VIEW);
        when(organizationService.getOrganizationById(ORG_ID)).thenReturn(OrganizationDto.builder().id(ORG_ID).build());

        assertThatCode(() -> organizationController.getOrganizationById(String.valueOf(ORG_ID)))
                .doesNotThrowAnyException();
        assertThatCode(() -> organizationController.getAllOrganizations()).doesNotThrowAnyException();
        assertThatCode(() -> dataRetentionController.getOrgRetention(ORG_ID)).doesNotThrowAnyException();
    }

    private void assertAllRefused(long organizationId) {
        organizationWrites(organizationId).forEach((name, write) ->
                assertThatThrownBy(write::execute).as(name).isInstanceOf(AccessDeniedException.class));
        verifyNoInteractions(organizationService, purgeService);
    }

    /** Signs in a caller whose token and database record both carry {@code roleNames}, which grant {@code permissions}. */
    private void signIn(Long organizationId, List<String> roleNames, String... permissions) {
        Organization organization = organizationId == null ? null : Organization.builder().id(organizationId).build();
        Set<Permission> granted = new HashSet<>();
        for (String name : permissions) {
            granted.add(Permission.builder().id((long) Math.abs(name.hashCode())).name(name).build());
        }
        Set<Role> roles = new HashSet<>();
        long roleId = 1;
        for (String roleName : roleNames) {
            boolean system = ROLE_ORGANIZATION_ADMIN.equals(roleName) || ROLE_SUPER_ADMIN.equals(roleName);
            roles.add(Role.builder().id(roleId++).name(roleName).isSystemRole(system)
                    .organization(system ? null : organization).permissions(granted).build());
        }
        User caller = User.builder().id(CALLER_ID).organization(organization).active(true)
                .roles(roles).permissions(new HashSet<>()).build();
        when(userRepository.findById(CALLER_ID)).thenReturn(Optional.of(caller));

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        roleNames.forEach(name -> authorities.add(new SimpleGrantedAuthority("ROLE_" + name)));
        for (String name : permissions) {
            authorities.add(new SimpleGrantedAuthority(name));
        }
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("caller", "n/a", authorities));
        GatewayRequestContext.set(CALLER_ID, organizationId == null ? null : String.valueOf(organizationId),
                "req", "caller@example.com");
    }

    private void demoteInDatabase() {
        User caller = userRepository.findById(CALLER_ID).orElseThrow();
        caller.getRoles().forEach(role -> role.setName("VIEWER"));
    }
}
