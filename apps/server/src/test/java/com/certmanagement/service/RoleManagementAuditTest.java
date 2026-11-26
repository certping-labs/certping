// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.role.CreateRoleRequest;
import com.certmanagement.dto.role.UpdateRolePermissionsRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PermissionGrantPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Every change to a role, a role assignment or a direct grant leaves one structured audit row. */
@ExtendWith(MockitoExtension.class)
class RoleManagementAuditTest {

    private static final long ORG_ID = 3L;
    private static final Organization ORGANIZATION = Organization.builder().id(ORG_ID).build();

    @Mock private RoleRepository roleRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private UserRepository userRepository;
    @Mock private PermissionGrantPolicy grantPolicy;
    @Mock private com.certmanagement.service.audit.AccessAuditRecorder accessAudit;

    private RoleManagementService service;

    private final Permission view = permission(1L, "domains:view");
    private final Permission manage = permission(2L, "domains:manage");
    private final Permission orgManage = permission(3L, "organization:manage");

    @BeforeEach
    void setUp() {
        service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository,
                userRepository, grantPolicy, accessAudit, new PermissionFeatureVisibility(org.mockito.Mockito.mock(FeatureFlagService.class)));
        lenient().when(permissionRepository.findByNameIn(anyCollection())).thenAnswer(i -> {
            Collection<String> names = i.getArgument(0);
            return List.of(view, manage, orgManage).stream().filter(p -> names.contains(p.getName())).toList();
        });
        lenient().when(roleRepository.save(any(Role.class))).thenAnswer(i -> {
            Role role = i.getArgument(0);
            if (role.getId() == null) {
                role.setId(40L);
            }
            return role;
        });
        lenient().when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));
        lenient().when(grantPolicy.assertDirectGrantsAllowed(any(), any(), any()))
                .thenAnswer(i -> new HashSet<Permission>(i.getArgument(2)));
    }

    @Test
    void createRole_recordsTheRoleAndItsPermissions() {
        when(organizationRepository.findById(ORG_ID)).thenReturn(Optional.of(ORGANIZATION));
        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("domain editor").permissionNames(Set.of("domains:manage", "domains:view")).build();

        service.createRole(request, ORG_ID);

        ArgumentCaptor<Role> created = ArgumentCaptor.forClass(Role.class);
        verify(accessAudit).roleCreated(created.capture());
        assertThat(created.getValue().getId()).isEqualTo(40L);
        assertThat(created.getValue().getName()).isEqualTo("DOMAIN EDITOR");
        assertThat(names(created.getValue().getPermissions())).containsExactly("domains:manage", "domains:view");
    }

    @Test
    void createRole_refusedByThePolicy_recordsNothing() {
        when(organizationRepository.findById(ORG_ID)).thenReturn(Optional.of(ORGANIZATION));
        doThrow(new AccessDeniedException("no")).when(grantPolicy).assertGrantable(any(), anyCollection());
        CreateRoleRequest request = CreateRoleRequest.builder().name("x").permissionNames(Set.of("domains:view")).build();

        assertThatThrownBy(() -> service.createRole(request, ORG_ID)).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(accessAudit);
    }

    @Test
    void updateRolePermissions_recordsBeforeAndAfter() {
        Role role = customRole(41L, "EDITOR", view);
        when(roleRepository.findById(41L)).thenReturn(Optional.of(role));
        UpdateRolePermissionsRequest request = UpdateRolePermissionsRequest.builder()
                .permissionNames(Set.of("domains:view", "domains:manage")).build();

        service.updateRolePermissions(41L, ORG_ID, request);

        verify(accessAudit).rolePermissionsChanged(org.mockito.ArgumentMatchers.argThat(r -> r.getId() == 41L),
                eq(List.of("domains:view")), eq(List.of("domains:manage", "domains:view")));
    }

    @Test
    void updateRolePermissions_withTheSameSet_recordsNothing() {
        when(roleRepository.findById(41L)).thenReturn(Optional.of(customRole(41L, "EDITOR", view)));
        UpdateRolePermissionsRequest request = UpdateRolePermissionsRequest.builder()
                .permissionNames(Set.of("domains:view")).build();

        service.updateRolePermissions(41L, ORG_ID, request);

        verifyNoInteractions(accessAudit);
    }

    @Test
    void deleteRole_recordsWhatTheRoleHeldAndHowManyUsersLostIt() {
        when(roleRepository.findById(41L)).thenReturn(Optional.of(customRole(41L, "EDITOR", view, manage)));
        when(roleRepository.softDeleteUserRolesByRoleId(41L)).thenReturn(2);

        service.deleteRole(41L, ORG_ID);

        verify(accessAudit).roleDeleted(org.mockito.ArgumentMatchers.argThat(r -> r.getId() == 41L),
                eq(List.of("domains:manage", "domains:view")), eq(2));
    }

    @Test
    void assignRolesToUser_recordsRolesBeforeAndAfterAndTheDirectGrantsItDropped() {
        Role editor = customRole(41L, "EDITOR", view);
        Role admin = Role.builder().id(1L).name("ORGANIZATION_ADMIN").isSystemRole(true).permissions(Set.of()).build();
        User user = user(9, Set.of(editor), Set.of(orgManage, view));
        when(userRepository.findByIdAndOrganizationId(9, ORG_ID)).thenReturn(Optional.of(user));
        when(roleRepository.findById(1L)).thenReturn(Optional.of(admin));
        when(grantPolicy.directGrantsAfterRoleChange(any(), any())).thenReturn(new HashSet<>(Set.of(view)));

        service.assignRolesToUser(9, ORG_ID, Set.of(1L));

        ArgumentCaptor<Collection<Role>> before = rolesCaptor();
        ArgumentCaptor<Collection<Role>> after = rolesCaptor();
        verify(accessAudit).memberRolesChanged(eq(user), before.capture(), after.capture(),
                eq(List.of("organization:manage")));
        assertThat(before.getValue()).extracting(Role::getName).containsExactly("EDITOR");
        assertThat(after.getValue()).extracting(Role::getName).containsExactly("ORGANIZATION_ADMIN");
    }

    @Test
    void setUserPermissions_recordsBeforeAndAfter() {
        when(userRepository.findByIdAndOrganizationId(9, ORG_ID)).thenReturn(Optional.of(user(9, Set.of(), Set.of(view))));

        service.setUserPermissions(9, ORG_ID, Set.of("domains:manage"));

        assertDirectGrantsRecorded(List.of("domains:view"), List.of("domains:manage"));
    }

    @Test
    void addUserPermissions_recordsBeforeAndAfter() {
        when(userRepository.findByIdAndOrganizationId(9, ORG_ID)).thenReturn(Optional.of(user(9, Set.of(), Set.of(view))));

        service.addUserPermissions(9, ORG_ID, Set.of("domains:manage"));

        assertDirectGrantsRecorded(List.of("domains:view"), List.of("domains:manage", "domains:view"));
    }

    @Test
    void removeUserPermissions_recordsBeforeAndAfter() {
        when(userRepository.findByIdAndOrganizationId(9, ORG_ID))
                .thenReturn(Optional.of(user(9, Set.of(), Set.of(view, manage))));

        service.removeUserPermissions(9, ORG_ID, Set.of("domains:manage"));

        assertDirectGrantsRecorded(List.of("domains:manage", "domains:view"), List.of("domains:view"));
    }

    @Test
    void removingAGrantTheUserDoesNotHave_recordsNothing() {
        when(userRepository.findByIdAndOrganizationId(9, ORG_ID)).thenReturn(Optional.of(user(9, Set.of(), Set.of(view))));

        service.removeUserPermissions(9, ORG_ID, Set.of("domains:manage"));

        verify(accessAudit, never()).memberPermissionsChanged(any(), any(), any());
    }

    private void assertDirectGrantsRecorded(List<String> before, List<String> after) {
        verify(accessAudit).memberPermissionsChanged(any(), eq(before), eq(after));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static ArgumentCaptor<Collection<Role>> rolesCaptor() {
        return (ArgumentCaptor) ArgumentCaptor.forClass(Collection.class);
    }

    private static List<String> names(Collection<Permission> permissions) {
        return permissions.stream().map(Permission::getName).sorted().toList();
    }

    private static Permission permission(long id, String name) {
        return Permission.builder().id(id).name(name).build();
    }

    private static Role customRole(long id, String name, Permission... permissions) {
        return Role.builder().id(id).name(name).organization(ORGANIZATION).isSystemRole(false)
                .permissions(new HashSet<>(Set.of(permissions))).build();
    }

    private static User user(int id, Set<Role> roles, Set<Permission> permissions) {
        return User.builder().id(id).organization(ORGANIZATION).active(true)
                .roles(new HashSet<>(roles)).permissions(new HashSet<>(permissions)).build();
    }
}
