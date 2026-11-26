// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.Organization;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.repository.RoleRepository;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleMappingServiceTest {

    @Mock private RoleRepository roleRepository;
    // Use a real ObjectMapper so the JSON role-mapping parse actually exercises.
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private RoleMappingService service;

    private RoleMappingService svc() {
        return new RoleMappingService(roleRepository, objectMapper);
    }

    private Organization org(Long id) {
        return Organization.builder().id(id).name("Org" + id).build();
    }

    private Role role(String name) {
        return Role.builder().id(1L).name(name).build();
    }

    @Test
    void mapIdpRolesToAppRoles_withDirectMatch_resolvesAppRole() {
        service = svc();
        SsoUserInfo info = SsoUserInfo.builder()
                .roles(Set.of("Admin"))
                .groups(Set.of())
                .build();
        SsoConfig cfg = SsoConfig.builder()
                .roleMapping("{\"Admin\":\"ORGANIZATION_ADMIN\"}")
                .build();
        when(roleRepository.findByNameAndOrganizationIsNull("ORGANIZATION_ADMIN"))
                .thenReturn(java.util.Optional.of(role("ORGANIZATION_ADMIN")));

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);

        assertThat(roles).extracting(Role::getName).containsExactly("ORGANIZATION_ADMIN");
    }

    @Test
    void mapIdpRolesToAppRoles_caseInsensitiveMatch_resolvesOrganizationRole() {
        service = svc();
        SsoUserInfo info = SsoUserInfo.builder()
                .roles(Set.of("admin"))      // lowercase -> needs case-insensitive match
                .groups(Set.of())
                .build();
        SsoConfig cfg = SsoConfig.builder()
                .organization(org(42L))
                .roleMapping("{\"Admin\":\"ORG_ADMIN\"}")
                .build();
        // Not a system role -> falls back to this organization's own roles.
        when(roleRepository.findByNameAndOrganizationIsNull("ORG_ADMIN"))
                .thenReturn(java.util.Optional.empty());
        when(roleRepository.findByNameAndOrganizationId("ORG_ADMIN", 42L))
                .thenReturn(java.util.Optional.of(role("ORG_ADMIN")));

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);

        assertThat(roles).extracting(Role::getName).containsExactly("ORG_ADMIN");
    }

    /**
     * SUPER_ADMIN is platform-wide. The role-mapping JSON is written by the customer's own IdP
     * administrator, so allowing it there would let any tenant mint platform administrators.
     */
    @Test
    void mapIdpRolesToAppRoles_refusesToGrantSuperAdmin() {
        service = svc();
        SsoUserInfo info = SsoUserInfo.builder()
                .roles(Set.of())
                .groups(Set.of("Tenant-Admins"))
                .build();
        SsoConfig cfg = SsoConfig.builder()
                .organization(org(42L))
                .roleMapping("{\"Tenant-Admins\":\"SUPER_ADMIN\"}")
                .build();
        when(roleRepository.findByNameAndOrganizationIsNull("VIEWER"))
                .thenReturn(java.util.Optional.of(role("VIEWER")));

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);

        assertThat(roles).extracting(Role::getName).doesNotContain("SUPER_ADMIN");
        assertThat(roles).extracting(Role::getName).containsExactly("VIEWER");
        verify(roleRepository, never()).findByNameAndOrganizationId(eq("SUPER_ADMIN"), any());
    }

    /** Another organization's identically-named role must never be attached to this tenant's user. */
    @Test
    void mapIdpRolesToAppRoles_doesNotLeakRoleFromAnotherOrganization() {
        service = svc();
        SsoUserInfo info = SsoUserInfo.builder()
                .roles(Set.of())
                .groups(Set.of("Managers"))
                .build();
        SsoConfig cfg = SsoConfig.builder()
                .organization(org(42L))
                .roleMapping("{\"Managers\":\"CUSTOM_ROLE\"}")
                .build();
        when(roleRepository.findByNameAndOrganizationIsNull("CUSTOM_ROLE"))
                .thenReturn(java.util.Optional.empty());
        // Org 42 has no such role; org 99's role of the same name must not be reachable.
        when(roleRepository.findByNameAndOrganizationId("CUSTOM_ROLE", 42L))
                .thenReturn(java.util.Optional.empty());
        when(roleRepository.findByNameAndOrganizationIsNull("VIEWER"))
                .thenReturn(java.util.Optional.of(role("VIEWER")));

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);

        assertThat(roles).extracting(Role::getName).containsExactly("VIEWER");
    }

    /** Defence in depth for configs saved before default roles were validated. */
    @Test
    void getDefaultRole_refusesSuperAdminAndFallsBackToViewer() {
        service = svc();
        SsoConfig cfg = SsoConfig.builder()
                .organization(org(42L))
                .registrationId("org-42-azure-oidc")
                .defaultRole(role("SUPER_ADMIN"))
                .build();
        when(roleRepository.findByNameAndOrganizationIsNull("VIEWER"))
                .thenReturn(java.util.Optional.of(role("VIEWER")));

        Set<Role> roles = service.getDefaultRole(cfg);

        assertThat(roles).extracting(Role::getName).containsExactly("VIEWER");
    }

    @Test
    void mapIdpRolesToAppRoles_groupsAlsoConsidered() {
        service = svc();
        SsoUserInfo info = SsoUserInfo.builder()
                .roles(Set.of())
                .groups(Set.of("Viewers"))
                .build();
        SsoConfig cfg = SsoConfig.builder()
                .roleMapping("{\"Viewers\":\"VIEWER\"}")
                .build();
        when(roleRepository.findByNameAndOrganizationIsNull("VIEWER"))
                .thenReturn(java.util.Optional.of(role("VIEWER")));

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);
        assertThat(roles).extracting(Role::getName).containsExactly("VIEWER");
    }

    @Test
    void mapIdpRolesToAppRoles_invalidJson_returnsDefaultRole() {
        service = svc();
        SsoUserInfo info = SsoUserInfo.builder().roles(Set.of("Admin")).groups(Set.of()).build();
        SsoConfig cfg = SsoConfig.builder()
                .roleMapping("not-json")
                .defaultRole(role("VIEWER"))
                .build();

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);

        // parse failed -> empty -> default role used
        assertThat(roles).extracting(Role::getName).containsExactly("VIEWER");
    }

    @Test
    void mapIdpRolesToAppRoles_noMappingConfigured_usesDefaultRole() {
        service = svc();
        SsoUserInfo info = SsoUserInfo.builder().roles(Set.of()).groups(Set.of()).build();
        SsoConfig cfg = SsoConfig.builder().defaultRole(role("VIEWER")).build();

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);
        assertThat(roles).extracting(Role::getName).containsExactly("VIEWER");
    }

    @Test
    void mapIdpRolesToAppRoles_nullRolesAndGroups_doesNotThrow() {
        service = svc();
        SsoUserInfo info = new SsoUserInfo();
        info.setRoles(null);
        info.setGroups(null);
        SsoConfig cfg = SsoConfig.builder().defaultRole(role("VIEWER")).build();

        Set<Role> roles = service.mapIdpRolesToAppRoles(info, cfg);
        assertThat(roles).extracting(Role::getName).containsExactly("VIEWER");
    }

    @Test
    void getDefaultRole_withConfiguredDefault_returnsIt() {
        service = svc();
        SsoConfig cfg = SsoConfig.builder().defaultRole(role("CUSTOM")).build();
        assertThat(service.getDefaultRole(cfg)).extracting(Role::getName).containsExactly("CUSTOM");
    }

    @Test
    void getDefaultRole_withoutConfiguredDefault_fallsBackToViewer() {
        service = svc();
        SsoConfig cfg = SsoConfig.builder().build();
        when(roleRepository.findByNameAndOrganizationIsNull("VIEWER"))
                .thenReturn(java.util.Optional.of(role("VIEWER")));

        assertThat(service.getDefaultRole(cfg)).extracting(Role::getName).containsExactly("VIEWER");
    }

    @Test
    void getDefaultRole_viewerMissing_returnsEmpty() {
        service = svc();
        SsoConfig cfg = SsoConfig.builder().build();
        when(roleRepository.findByNameAndOrganizationIsNull("VIEWER"))
                .thenReturn(java.util.Optional.empty());

        assertThat(service.getDefaultRole(cfg)).isEmpty();
    }

    @Test
    void shouldSyncRolesOnFirstLogin_reflectsConfigFlag() {
        service = svc();
        SsoConfig on = SsoConfig.builder().syncRolesOnFirstLogin(true).build();
        SsoConfig off = SsoConfig.builder().syncRolesOnFirstLogin(false).build();
        SsoConfig explicitNull = SsoConfig.builder().syncRolesOnFirstLogin(null).build();

        assertThat(service.shouldSyncRolesOnFirstLogin(on)).isTrue();
        assertThat(service.shouldSyncRolesOnFirstLogin(off)).isFalse();
        // null flag is not Boolean.TRUE -> false
        assertThat(service.shouldSyncRolesOnFirstLogin(explicitNull)).isFalse();
    }
}
