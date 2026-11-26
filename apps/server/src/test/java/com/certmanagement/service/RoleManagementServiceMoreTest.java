// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import org.junit.jupiter.api.BeforeEach;
import com.certmanagement.dto.permission.PermissionDto;
import com.certmanagement.dto.role.UpdateRolePermissionsRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.Permissions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleManagementServiceMoreTest {

    @Mock private RoleRepository roleRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private UserRepository userRepository;
    @Mock private PermissionGrantPolicy grantPolicy;

    @BeforeEach
    void policyPassesGrantsThrough() {
        lenient().when(grantPolicy.assertDirectGrantsAllowed(any(), any(), any()))
                .thenAnswer(i -> new HashSet<Permission>(i.getArgument(2)));
        lenient().when(grantPolicy.directGrantsAfterRoleChange(any(), any()))
                .thenAnswer(i -> new HashSet<>(i.<User>getArgument(0).getPermissions()));
        lenient().when(grantPolicy.isGrantableBy(any(), anyString())).thenReturn(true);
    }

    private RoleManagementService service() {
        return new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    private void asSuperAdmin() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("sa", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_" + Permissions.ROLE_SUPER_ADMIN))));
    }

    private Permission perm(long id, String name) {
        return Permission.builder().id(id).name(name).resource("r").action("a").description("d").build();
    }

    private Role customRole(long id, long orgId) {
        return Role.builder().id(id).name("CUSTOM").isSystemRole(false)
                .organization(Organization.builder().id(orgId).build())
                .permissions(new HashSet<>()).build();
    }

    // ── updateRolePermissions ────────────────────────────────────────────────

    @Test
    void updateRolePermissions_customRoleSucceeds() {
        asSuperAdmin();
        Role role = customRole(5L, 1L);
        when(roleRepository.findById(5L)).thenReturn(Optional.of(role));
        Permission p = perm(20L, Permissions.USERS_VIEW);
        when(permissionRepository.findByNameIn(Set.of(Permissions.USERS_VIEW))).thenReturn(List.of(p));
        when(roleRepository.save(any(Role.class))).thenAnswer(i -> i.getArgument(0));

        var req = new UpdateRolePermissionsRequest();
        req.setPermissionNames(Set.of(Permissions.USERS_VIEW));
        var dto = service().updateRolePermissions(5L, 1L, req);

        assertThat(dto.getPermissions()).contains(Permissions.USERS_VIEW);
        verify(roleRepository).save(role);
    }

    @Test
    void updateRolePermissions_systemRoleRejected() {
        asSuperAdmin();
        Role sys = Role.builder().id(6L).name("SOME_SYS").isSystemRole(true)
                .organization(Organization.builder().id(1L).build()).build();
        when(roleRepository.findById(6L)).thenReturn(Optional.of(sys));
        var req = new UpdateRolePermissionsRequest();
        req.setPermissionNames(Set.of(Permissions.USERS_VIEW));

        assertThatThrownBy(() -> service().updateRolePermissions(6L, 1L, req))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("System role permissions cannot be modified");
    }

    @Test
    void getRolePermissions_returnsMappedDtos() {
        Role role = Role.builder().id(2L).name("REG_SYS").isSystemRole(true).organization(null)
                .permissions(Set.of(perm(1L, Permissions.USERS_VIEW))).build();
        when(roleRepository.findById(2L)).thenReturn(Optional.of(role));
        Set<PermissionDto> dtos = service().getRolePermissions(2L, 1L);
        assertThat(dtos).extracting(PermissionDto::getName).contains(Permissions.USERS_VIEW);
    }

    @Test
    void getUserPermissions_returnsMappedDtos() {
        User user = User.builder().id(3).organization(Organization.builder().id(1L).build())
                .permissions(Set.of(perm(1L, Permissions.USERS_VIEW))).roles(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(3, 1L)).thenReturn(Optional.of(user));
        Set<PermissionDto> dtos = service().getUserPermissions(3, 1L);
        assertThat(dtos).extracting(PermissionDto::getName).contains(Permissions.USERS_VIEW);
    }

    @Test
    void loadUserInScope_nullOrgUsesGlobalLookup() {
        User user = User.builder().id(3).permissions(new HashSet<>()).roles(new HashSet<>()).build();
        when(userRepository.findById(3)).thenReturn(Optional.of(user));
        assertThat(service().getUserPermissions(3, null)).isEmpty();
    }

    @Test
    void loadUserInScope_userNotFoundThrows() {
        when(userRepository.findByIdAndOrganizationId(99, 1L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service().getUserPermissions(99, 1L))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ── set/add/remove user permissions ──────────────────────────────────────

    @Test
    void setUserPermissions_replacesGrants() {
        User user = User.builder().id(3).organization(Organization.builder().id(1L).build())
                .permissions(new HashSet<>(Set.of(perm(9L, "old:perm")))).roles(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(3, 1L)).thenReturn(Optional.of(user));
        when(permissionRepository.findByNameIn(Set.of(Permissions.USERS_VIEW)))
                .thenReturn(List.of(perm(1L, Permissions.USERS_VIEW)));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        Set<PermissionDto> result = service().setUserPermissions(3, 1L, Set.of(Permissions.USERS_VIEW));
        assertThat(result).extracting(PermissionDto::getName).containsExactly(Permissions.USERS_VIEW);
    }

    @Test
    void addUserPermissions_unionsWithExisting() {
        User user = User.builder().id(3).organization(Organization.builder().id(1L).build())
                .permissions(new HashSet<>(Set.of(perm(9L, "existing:perm")))).roles(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(3, 1L)).thenReturn(Optional.of(user));
        when(permissionRepository.findByNameIn(Set.of(Permissions.USERS_VIEW)))
                .thenReturn(List.of(perm(1L, Permissions.USERS_VIEW)));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        Set<PermissionDto> result = service().addUserPermissions(3, 1L, Set.of(Permissions.USERS_VIEW));
        assertThat(result).extracting(PermissionDto::getName)
                .contains(Permissions.USERS_VIEW, "existing:perm");
    }

    @Test
    void removeUserPermissions_removesSpecified() {
        Permission keep = perm(9L, "keep:perm");
        Permission drop = perm(1L, Permissions.USERS_VIEW);
        User user = User.builder().id(3).organization(Organization.builder().id(1L).build())
                .permissions(new HashSet<>(Set.of(keep, drop))).roles(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(3, 1L)).thenReturn(Optional.of(user));
        when(permissionRepository.findByNameIn(Set.of(Permissions.USERS_VIEW))).thenReturn(List.of(drop));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        Set<PermissionDto> result = service().removeUserPermissions(3, 1L, Set.of(Permissions.USERS_VIEW));
        assertThat(result).extracting(PermissionDto::getName).containsExactly("keep:perm");
    }

    // ── resolvePermissions error path ────────────────────────────────────────

    @Test
    void resolvePermissions_unknownNamesThrows() {
        User user = User.builder().id(3).organization(Organization.builder().id(1L).build())
                .permissions(new HashSet<>()).roles(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(3, 1L)).thenReturn(Optional.of(user));
        when(permissionRepository.findByNameIn(any())).thenReturn(List.of(perm(1L, "known:perm")));

        assertThatThrownBy(() -> service().setUserPermissions(3, 1L, Set.of("known:perm", "missing:perm")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Unknown permissions")
                .hasMessageContaining("missing:perm");
    }

    // ── getPermissionsByResource / getAllPermissions overloads ───────────────

    @Test
    void getPermissionsByResource_orgOverloadDelegates() {
        when(permissionRepository.findByResourceOrderByCreatedAtDesc("certs"))
                .thenReturn(List.of(perm(1L, "certs:view")));
        assertThat(service().getPermissionsByResource("certs", 1L))
                .extracting(PermissionDto::getName).containsExactly("certs:view");
    }

    @Test
    void getAllPermissions_orgOverloadDelegates() {
        when(permissionRepository.findAllByOrderByCreatedAtDesc())
                .thenReturn(List.of(perm(1L, "certs:view")));
        assertThat(service().getAllPermissions(1L)).hasSize(1);
    }

    @Test
    void organizationScopedListsLeaveOutThePlatformPermissions() {
        List<Permission> all = List.of(perm(1L, "certs:view"), perm(2L, Permissions.FEATURE_FLAGS_ADMINISTER));
        when(permissionRepository.findAllByOrderByCreatedAtDesc()).thenReturn(all);
        when(permissionRepository.findByResourceOrderByCreatedAtDesc("feature_flags")).thenReturn(all);

        assertThat(service().getAllPermissions(1L)).extracting(PermissionDto::getName).containsExactly("certs:view");
        assertThat(service().getPermissionsByResource("feature_flags", 1L))
                .extracting(PermissionDto::getName).containsExactly("certs:view");
        assertThat(service().getAllPermissions()).hasSize(2);
    }

    // ── resolveAssignableRole AccessDenied (org mismatch) ────────────────────

    @Test
    void assignRolesToUser_customRoleFromOtherOrgNotVisible() {
        asSuperAdmin();
        // custom role belongs to org 2, but assigning under org 1 -> not visible
        Role role = customRole(10L, 2L);
        User user = User.builder().id(1).organization(Organization.builder().id(1L).build())
                .roles(new HashSet<>()).permissions(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(1, 1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

        assertThatThrownBy(() -> service().assignRolesToUser(1, 1L, Set.of(10L)))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ── validatePrivilegedRolePermissionPolicy: SUPER_ADMIN role with disallowed perms ──

    @Test
    void assignRolesToUser_superAdminRoleWithUnsupportedPermissionRejected() {
        asSuperAdmin();
        Role superAdminRole = Role.builder().id(11L).name(Permissions.ROLE_SUPER_ADMIN)
                .isSystemRole(true).organization(null)
                .permissions(Set.of(perm(1L, "certificates:delete"))) // not in SUPER_ADMIN_ALLOWED
                .build();
        User user = User.builder().id(1).organization(Organization.builder().id(1L).build())
                .roles(new HashSet<>()).permissions(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(1, 1L)).thenReturn(Optional.of(user));
        when(roleRepository.findById(11L)).thenReturn(Optional.of(superAdminRole));

        assertThatThrownBy(() -> service().assignRolesToUser(1, 1L, Set.of(11L)))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("unsupported permissions");
    }

    // ── isCurrentUserSuperAdminEffective via persisted caller role ───────────

    @Test
    void assignRolesToUser_emptyRoleSetSucceedsNoValidation() {
        asSuperAdmin();
        User target = User.builder().id(1).organization(Organization.builder().id(1L).build())
                .roles(new HashSet<>()).permissions(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(1, 1L)).thenReturn(Optional.of(target));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        service().assignRolesToUser(1, 1L, Set.of());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void assignRolesToUser_regularRoleSuccessExercisesEffectiveChecks() {
        // Caller is super via JWT (so super-admin role would be viewable too), but here we
        // assign a plain regular system role -> validatePrivilegedRoleAssignment passes through
        // both assignsSuperAdmin=false and assignsOrganizationAdmin=false branches.
        asSuperAdmin();
        Role regularRole = Role.builder().id(14L).name("VIEWER").isSystemRole(true).organization(null)
                .permissions(new HashSet<>()).build();
        User target = User.builder().id(1).organization(Organization.builder().id(1L).build())
                .roles(new HashSet<>()).permissions(new HashSet<>()).build();
        when(userRepository.findByIdAndOrganizationId(1, 1L)).thenReturn(Optional.of(target));
        when(roleRepository.findById(14L)).thenReturn(Optional.of(regularRole));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        service().assignRolesToUser(1, 1L, Set.of(14L));
        verify(userRepository).save(any(User.class));
    }
}
