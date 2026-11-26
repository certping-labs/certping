// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import org.junit.jupiter.api.BeforeEach;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.Permissions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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
class RoleManagementServiceTest {

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

    @AfterEach
    void cleanupSecurityContext() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    @Test
    void assignRolesToUser_superAdminCanAssignOrganizationAdmin() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 2L;

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_" + Permissions.ROLE_SUPER_ADMIN))));

        Permission permission = Permission.builder().id(20L).name("users:manage").build();
        Role organizationAdminRole = Role.builder()
                .id(10L)
                .name(Permissions.ROLE_ORGANIZATION_ADMIN)
                .isSystemRole(true)
                .permissions(Set.of(permission))
                .build();
        User user = User.builder()
                .id(1)
                .organization(Organization.builder().id(organizationId).build())
                .roles(new HashSet<>())
                .permissions(new HashSet<>())
                .build();

        when(userRepository.findByIdAndOrganizationId(1, organizationId)).thenReturn(Optional.of(user));
        when(roleRepository.findById(10L)).thenReturn(Optional.of(organizationAdminRole));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.assignRolesToUser(1, organizationId, Set.of(10L));

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getRoleNames()).contains(Permissions.ROLE_ORGANIZATION_ADMIN);
        assertThat(saved.getPermissionNames()).isEmpty(); // role assignment does not stamp individual grants
        assertThat(saved.getEffectivePermissionNames()).contains("users:manage"); // role provides it via the union
        // The user's current access tokens carry the old roles: they are refused from now on.
        verify(userRepository).markTokensValidAfter(org.mockito.ArgumentMatchers.eq(1), any());
    }

    @Test
    void assignRolesToUser_preservesExistingIndividualPermissionGrants() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 14L;

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_" + Permissions.ROLE_SUPER_ADMIN))));

        Permission existingGrant = Permission.builder().id(30L).name("certificates:delete").build();
        Permission rolePermission = Permission.builder().id(20L).name("users:manage").build();
        Role organizationAdminRole = Role.builder()
                .id(10L)
                .name(Permissions.ROLE_ORGANIZATION_ADMIN)
                .isSystemRole(true)
                .permissions(Set.of(rolePermission))
                .build();
        User user = User.builder()
                .id(1)
                .organization(Organization.builder().id(organizationId).build())
                .roles(new HashSet<>())
                .permissions(new HashSet<>(Set.of(existingGrant)))
                .build();

        when(userRepository.findByIdAndOrganizationId(1, organizationId)).thenReturn(Optional.of(user));
        when(roleRepository.findById(10L)).thenReturn(Optional.of(organizationAdminRole));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.assignRolesToUser(1, organizationId, Set.of(10L));

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getPermissionNames()).containsExactly("certificates:delete"); // unchanged
        assertThat(saved.getEffectivePermissionNames()).containsExactlyInAnyOrder("certificates:delete", "users:manage");
    }

    @Test
    void assignRolesToUser_organizationAdminCanAssignOrganizationAdminWithinOrganization() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 12L;

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "organization-admin", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_" + Permissions.ROLE_ORGANIZATION_ADMIN))));

        Permission permission = Permission.builder().id(20L).name("users:manage").build();
        Role organizationAdminRole = Role.builder()
                .id(10L)
                .name(Permissions.ROLE_ORGANIZATION_ADMIN)
                .isSystemRole(true)
                .permissions(Set.of(permission))
                .build();
        User user = User.builder()
                .id(1)
                .organization(Organization.builder().id(organizationId).build())
                .roles(new HashSet<>())
                .permissions(new HashSet<>())
                .build();

        when(userRepository.findByIdAndOrganizationId(1, organizationId)).thenReturn(Optional.of(user));
        when(roleRepository.findById(10L)).thenReturn(Optional.of(organizationAdminRole));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.assignRolesToUser(1, organizationId, Set.of(10L));

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getRoleNames()).contains(Permissions.ROLE_ORGANIZATION_ADMIN);
    }

    @Test
    void assignRolesToUser_superAdminWithoutOrganizationScopeLoadsTargetGlobally() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_" + Permissions.ROLE_SUPER_ADMIN))));

        Role organizationAdminRole = Role.builder()
                .id(10L)
                .name(Permissions.ROLE_ORGANIZATION_ADMIN)
                .isSystemRole(true)
                .permissions(Set.of())
                .build();
        User target = User.builder()
                .id(1)
                .roles(new HashSet<>())
                .permissions(new HashSet<>())
                .build();

        when(userRepository.findById(1)).thenReturn(Optional.of(target));
        when(roleRepository.findById(10L)).thenReturn(Optional.of(organizationAdminRole));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.assignRolesToUser(1, null, Set.of(10L));

        verify(userRepository).findById(1);
        verify(userRepository).save(any(User.class));
    }

    @Test
    void createRole_persistsOrganizationAssociation() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 3L;
        Organization organization = Organization.builder().id(organizationId).name("Acme").domain("acme.example").active(true).build();
        Permission usersView = Permission.builder().id(1L).name("users:view").build();

        com.certmanagement.dto.role.CreateRoleRequest request = com.certmanagement.dto.role.CreateRoleRequest.builder()
                .name("ops_viewer")
                .description("ops")
                .permissionNames(Set.of("users:view"))
                .build();

        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(roleRepository.findByNameAndOrganizationIsNull("OPS_VIEWER")).thenReturn(Optional.empty());
        when(roleRepository.findByNameAndOrganizationId("OPS_VIEWER", organizationId)).thenReturn(Optional.empty());
        when(permissionRepository.findByNameIn(Set.of("users:view"))).thenReturn(List.of(usersView));
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.createRole(request, organizationId);

        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(captor.capture());
        assertThat(captor.getValue().getOrganization()).isNotNull();
        assertThat(captor.getValue().getOrganization().getId()).isEqualTo(organizationId);
    }

    @Test
    void getAllPermissions_usesCreatedAtOrderedRepositoryMethod() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 4L;
        Permission p = Permission.builder().id(10L).name("users:view").resource("users").action("view").build();

        when(permissionRepository.findAllByOrderByCreatedAtDesc()).thenReturn(List.of(p));

        service.getAllPermissions(organizationId);

        verify(permissionRepository).findAllByOrderByCreatedAtDesc();
    }

    @Test
    void getPermissionsByResource_usesCreatedAtOrderedRepositoryMethod() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 5L;
        Permission p = Permission.builder().id(11L).name("roles:view").resource("roles").action("view").build();

        when(permissionRepository.findByResourceOrderByCreatedAtDesc("roles")).thenReturn(List.of(p));

        service.getPermissionsByResource("roles", organizationId);

        verify(permissionRepository).findByResourceOrderByCreatedAtDesc("roles");
    }

    @Test
    void getAllRoles_nonSuperAdminHidesSuperAdminAndShowsOrganizationRoles() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 6L;
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("organization-user", "n/a", List.of()));

        Role superAdmin = Role.builder().id(1L).name(Permissions.ROLE_SUPER_ADMIN).isSystemRole(true).build();
        Role organizationAdmin = Role.builder().id(2L).name(Permissions.ROLE_ORGANIZATION_ADMIN).isSystemRole(true).build();
        Role custom = Role.builder().id(3L).name("OPS_VIEWER").isSystemRole(false)
                .organization(Organization.builder().id(organizationId).build()).build();

        when(roleRepository.findByIsSystemRoleTrueOrderByUpdatedAtDesc()).thenReturn(List.of(superAdmin, organizationAdmin));
        when(roleRepository.findByOrganizationIdOrderByUpdatedAtDesc(organizationId)).thenReturn(List.of(custom));

        List<com.certmanagement.dto.role.RoleDto> roles = service.getAllRoles(organizationId);

        assertThat(roles).extracting(com.certmanagement.dto.role.RoleDto::getName)
                .contains(Permissions.ROLE_ORGANIZATION_ADMIN, "OPS_VIEWER")
                .doesNotContain(Permissions.ROLE_SUPER_ADMIN);
    }

    @Test
    void getAllRoles_nullOrganizationForNonSuperReturnsOnlyRegularSystemRoles() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("platform-user", "n/a", List.of()));

        Role superAdmin = Role.builder().id(1L).name(Permissions.ROLE_SUPER_ADMIN).isSystemRole(true).build();
        Role organizationAdmin = Role.builder().id(2L).name(Permissions.ROLE_ORGANIZATION_ADMIN).isSystemRole(true).build();

        when(roleRepository.findByIsSystemRoleTrueOrderByUpdatedAtDesc()).thenReturn(List.of(superAdmin, organizationAdmin));

        List<com.certmanagement.dto.role.RoleDto> roles = service.getAllRoles((Long) null);

        assertThat(roles).extracting(com.certmanagement.dto.role.RoleDto::getName)
                .contains(Permissions.ROLE_ORGANIZATION_ADMIN)
                .doesNotContain(Permissions.ROLE_SUPER_ADMIN);
    }

    @Test
    void getRoleById_nonSuperCannotViewSuperAdminRole() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 99L;
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("organization-user", "n/a", List.of()));

        Role superAdmin = Role.builder().id(99L).name(Permissions.ROLE_SUPER_ADMIN).isSystemRole(true).build();
        when(roleRepository.findById(99L)).thenReturn(Optional.of(superAdmin));

        assertThatThrownBy(() -> service.getRoleById(99L, organizationId))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void createRole_normalizesNameBeforeSystemRoleCollisionCheck() {
        RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        Long organizationId = 100L;
        Organization organization = Organization.builder().id(organizationId).name("Acme").domain("acme.example").active(true).build();
        Role superAdminSystemRole = Role.builder().id(1L).name(Permissions.ROLE_SUPER_ADMIN).isSystemRole(true).build();

        com.certmanagement.dto.role.CreateRoleRequest request = com.certmanagement.dto.role.CreateRoleRequest.builder()
                .name("super_admin")
                .description("should collide")
                .permissionNames(Set.of())
                .build();

        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(roleRepository.findByNameAndOrganizationIsNull(Permissions.ROLE_SUPER_ADMIN)).thenReturn(Optional.of(superAdminSystemRole));

        assertThatThrownBy(() -> service.createRole(request, organizationId))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class)
                .hasMessageContaining(Permissions.ROLE_SUPER_ADMIN);
    }

        @Test
        void deleteRole_setsIsDeletedForOrganizationOwnedCustomRole() {
                RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
                Long organizationId = 7L;
                Long roleId = 77L;
                Role customRole = Role.builder()
                                .id(roleId)
                                .name("OPS_VIEWER")
                                .isSystemRole(false)
                                .isDeleted(false)
                                .organization(Organization.builder().id(organizationId).build())
                                .build();
                when(roleRepository.findById(roleId)).thenReturn(Optional.of(customRole));

                service.deleteRole(roleId, organizationId);

                ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
                verify(roleRepository).save(roleCaptor.capture());
                assertThat(roleCaptor.getValue().getIsDeleted()).isTrue();
        }

        @Test
        void deleteRole_cascadesSoftDeleteToUserRolesAndRolePermissions() {
                RoleManagementService service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository, userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
                Long organizationId = 7L;
                Long roleId = 77L;
                Role customRole = Role.builder()
                                .id(roleId)
                                .name("OPS_VIEWER")
                                .isSystemRole(false)
                                .isDeleted(false)
                                .organization(Organization.builder().id(organizationId).build())
                                .build();
                when(roleRepository.findById(roleId)).thenReturn(Optional.of(customRole));

                service.deleteRole(roleId, organizationId);

                verify(roleRepository).softDeleteUserRolesByRoleId(roleId);
                verify(roleRepository).softDeleteRolePermissionsByRoleId(roleId);
        }
}
