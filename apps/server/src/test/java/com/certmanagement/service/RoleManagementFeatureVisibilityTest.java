// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.permission.PermissionDto;
import com.certmanagement.dto.role.RoleDto;
import com.certmanagement.dto.role.UpdateRolePermissionsRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Permission;
import com.certmanagement.entity.Role;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.PermissionRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.PermissionGrantPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Permissions follow flags: hidden when the feature is off, never stripped by a save, never added. */
@ExtendWith(MockitoExtension.class)
class RoleManagementFeatureVisibilityTest {

    private static final long ORG_ID = 3L;
    private static final Organization ORGANIZATION = Organization.builder().id(ORG_ID).build();

    @Mock private RoleRepository roleRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private UserRepository userRepository;
    @Mock private PermissionGrantPolicy grantPolicy;
    @Mock private FeatureFlagService featureFlagService;

    private RoleManagementService service;

    private final Permission certRead = permission(1L, "certificate:read", "certificate");
    private final Permission deviceView = permission(2L, "iot_device:view", "iot_device");
    private final Permission deviceManage = permission(3L, "iot_device:manage", "iot_device");
    private final Permission alertsView = permission(4L, "alerts:view", "alerts");

    @BeforeEach
    void setUp() {
        service = new RoleManagementService(roleRepository, permissionRepository, organizationRepository,
                userRepository, grantPolicy, org.mockito.Mockito.mock(com.certmanagement.service.audit.AccessAuditRecorder.class), new PermissionFeatureVisibility(featureFlagService));
        lenient().when(featureFlagService.disabledFeatureKeys(ORG_ID)).thenReturn(Set.of(FeatureFlags.IOT_DEVICE_MANAGEMENT));
        lenient().when(permissionRepository.findByNameIn(anyCollection())).thenAnswer(i -> {
            Collection<String> names = i.getArgument(0);
            return List.of(certRead, deviceView, deviceManage, alertsView).stream()
                    .filter(p -> names.contains(p.getName())).toList();
        });
        lenient().when(permissionRepository.findAllByOrderByCreatedAtDesc())
                .thenReturn(List.of(certRead, deviceView, deviceManage, alertsView));
        lenient().when(grantPolicy.isGrantableBy(any(), any())).thenReturn(true);
        lenient().when(roleRepository.save(any(Role.class))).thenAnswer(i -> i.getArgument(0));
        lenient().when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));
        lenient().when(grantPolicy.assertDirectGrantsAllowed(any(), any(), any()))
                .thenAnswer(i -> new HashSet<Permission>(i.getArgument(2)));
    }

    @Test
    void permissionList_leavesOutDisabledFeaturesAndCarriesTheFeatureKey() {
        List<PermissionDto> permissions = service.getAllPermissions(ORG_ID);

        assertThat(permissions).extracting(PermissionDto::getName)
                .containsExactlyInAnyOrder("certificate:read", "alerts:view");
        assertThat(permissions).filteredOn(p -> p.getName().equals("alerts:view"))
                .extracting(PermissionDto::getFeatureKey).containsExactly(FeatureFlags.ALERTS);
        assertThat(permissions).filteredOn(p -> p.getName().equals("certificate:read"))
                .extracting(PermissionDto::getFeatureKey).containsNull();
    }

    @Test
    void superAdminPlatformView_hidesNothingAndReadsNoFlags() {
        assertThat(service.getAllPermissions()).hasSize(4);
        verify(featureFlagService, never()).disabledFeatureKeys(any());
    }

    @Test
    void roleList_omitsRolesMadeOnlyOfHiddenPermissions_andTrimsTheRest() {
        Role deviceOnly = customRole(10L, "DEVICES_ONLY", deviceView, deviceManage);
        Role mixed = customRole(11L, "MIXED", certRead, deviceView);
        when(roleRepository.findByIsSystemRoleTrueOrderByUpdatedAtDesc()).thenReturn(List.of());
        when(roleRepository.findByOrganizationIdOrderByUpdatedAtDesc(ORG_ID)).thenReturn(List.of(deviceOnly, mixed));

        List<RoleDto> roles = service.getAllRoles(ORG_ID);

        assertThat(roles).extracting(RoleDto::getName).containsExactly("MIXED");
        assertThat(roles.get(0).getPermissions()).containsExactly("certificate:read");
        verify(featureFlagService, times(1)).disabledFeatureKeys(ORG_ID);
    }

    @Test
    void roleUpdate_keepsHiddenPermissionsTheRoleAlreadyHas() {
        Role role = customRole(12L, "MIXED", certRead, deviceView);
        when(roleRepository.findById(12L)).thenReturn(Optional.of(role));

        RoleDto saved = service.updateRolePermissions(12L, ORG_ID,
                UpdateRolePermissionsRequest.builder().permissionNames(Set.of("alerts:view")).build());

        assertThat(role.getPermissions()).extracting(Permission::getName)
                .containsExactlyInAnyOrder("alerts:view", "iot_device:view");
        assertThat(saved.getPermissions()).containsExactly("alerts:view");
    }

    @Test
    void roleUpdate_cannotAddAPermissionOfADisabledFeature() {
        Role role = customRole(13L, "MIXED", certRead);
        when(roleRepository.findById(13L)).thenReturn(Optional.of(role));

        assertThatThrownBy(() -> service.updateRolePermissions(13L, ORG_ID,
                UpdateRolePermissionsRequest.builder().permissionNames(Set.of("certificate:read", "iot_device:manage")).build()))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Permissions [iot_device:manage] aren't available. Ask your CertPing administrator.");
        verify(roleRepository, never()).save(any());
    }

    @Test
    void userSet_keepsHiddenDirectGrants_andRemoveCannotStripThem() {
        User user = user(new HashSet<>(Set.of(certRead, deviceView)));
        when(userRepository.findById(7)).thenReturn(Optional.of(user));

        Set<PermissionDto> afterSet = service.setUserPermissions(7, null, Set.of("alerts:view"));
        assertThat(user.getPermissions()).extracting(Permission::getName)
                .containsExactlyInAnyOrder("alerts:view", "iot_device:view");
        assertThat(afterSet).extracting(PermissionDto::getName).containsExactly("alerts:view");

        service.removeUserPermissions(7, null, Set.of("iot_device:view", "alerts:view"));
        assertThat(user.getPermissions()).extracting(Permission::getName).containsExactly("iot_device:view");
    }

    @Test
    void userAdd_cannotGrantAPermissionOfADisabledFeature() {
        User user = user(new HashSet<>(Set.of(certRead)));
        when(userRepository.findById(7)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.addUserPermissions(7, null, Set.of("iot_device:view")))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void userReads_followTheUsersOwnOrganization_evenForASuperAdminWithoutOne() {
        User user = user(new HashSet<>(Set.of(certRead, deviceView)));
        when(userRepository.findById(7)).thenReturn(Optional.of(user));

        assertThat(service.getUserPermissions(7, null)).extracting(PermissionDto::getName)
                .containsExactly("certificate:read");
        verify(featureFlagService).disabledFeatureKeys(ORG_ID);
    }

    @Test
    void systemRolesHiddenFor_namesRolesWhosePermissionsAreAllOff() {
        Role devices = Role.builder().id(20L).name("DEVICE_MANAGER").isSystemRole(true)
                .permissions(new HashSet<>(Set.of(deviceView, deviceManage))).build();
        Role viewer = Role.builder().id(21L).name("VIEWER").isSystemRole(true)
                .permissions(new HashSet<>(Set.of(certRead, deviceView))).build();
        when(roleRepository.findByIsSystemRoleTrueOrderByUpdatedAtDesc()).thenReturn(List.of(devices, viewer));

        assertThat(service.roleNamesHiddenFor(ORG_ID)).containsExactly("DEVICE_MANAGER");
    }

    @Test
    void userRoleSave_keepsTheHiddenRolesTheUserHolds() {
        Role deviceOnly = systemRole(30L, "DEVICE_MANAGER", deviceView, deviceManage);
        Role viewer = systemRole(31L, "VIEWER", certRead);
        Role alerts = systemRole(32L, "ALERTS_VIEWER", alertsView);
        User user = user(new HashSet<>());
        user.setRoles(new HashSet<>(Set.of(deviceOnly, viewer)));
        when(userRepository.findByIdAndOrganizationId(7, ORG_ID)).thenReturn(Optional.of(user));
        when(roleRepository.findById(32L)).thenReturn(Optional.of(alerts));
        when(grantPolicy.directGrantsAfterRoleChange(any(), any())).thenReturn(new HashSet<>());

        // The picker cannot show DEVICE_MANAGER, so the request only names what is visible.
        service.assignRolesToUser(7, ORG_ID, Set.of(32L));

        assertThat(user.getRoles()).extracting(Role::getName)
                .containsExactlyInAnyOrder("ALERTS_VIEWER", "DEVICE_MANAGER");
        verify(userRepository).save(user);
    }

    @Test
    void userRoleSave_cannotAddAHiddenRole() {
        Role deviceOnly = systemRole(30L, "DEVICE_MANAGER", deviceView, deviceManage);
        Role viewer = systemRole(31L, "VIEWER", certRead);
        User user = user(new HashSet<>());
        user.setRoles(new HashSet<>(Set.of(viewer)));
        when(userRepository.findByIdAndOrganizationId(7, ORG_ID)).thenReturn(Optional.of(user));
        when(roleRepository.findById(30L)).thenReturn(Optional.of(deviceOnly));
        when(roleRepository.findById(31L)).thenReturn(Optional.of(viewer));

        assertThatThrownBy(() -> service.assignRolesToUser(7, ORG_ID, Set.of(30L, 31L)))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Roles [DEVICE_MANAGER] aren't available. Ask your CertPing administrator.");
        assertThat(user.getRoles()).containsExactly(viewer);
        verify(userRepository, never()).save(any());
    }

    @Test
    void userRoleSave_mayKeepNamingAHiddenRoleTheUserAlreadyHolds() {
        Role deviceOnly = systemRole(30L, "DEVICE_MANAGER", deviceView, deviceManage);
        User user = user(new HashSet<>());
        user.setRoles(new HashSet<>(Set.of(deviceOnly)));
        when(userRepository.findByIdAndOrganizationId(7, ORG_ID)).thenReturn(Optional.of(user));
        when(roleRepository.findById(30L)).thenReturn(Optional.of(deviceOnly));
        when(grantPolicy.directGrantsAfterRoleChange(any(), any())).thenReturn(new HashSet<>());

        service.assignRolesToUser(7, ORG_ID, Set.of(30L));

        assertThat(user.getRoles()).containsExactly(deviceOnly);
    }

    @Test
    void roleNamesHiddenFor_includesTheOrganizationsOwnRoles() {
        Role deviceOnly = customRole(40L, "DEVICES_ONLY", deviceView);
        Role mixed = customRole(41L, "MIXED", certRead, deviceView);
        when(roleRepository.findByIsSystemRoleTrueOrderByUpdatedAtDesc()).thenReturn(List.of());
        when(roleRepository.findByOrganizationId(ORG_ID)).thenReturn(List.of(deviceOnly, mixed));

        assertThat(service.roleNamesHiddenFor(ORG_ID)).containsExactly("DEVICES_ONLY");
    }

    @Test
    void roleNamesHiddenFor_readsNoRolesWhenNothingIsOff() {
        when(featureFlagService.disabledFeatureKeys(ORG_ID)).thenReturn(Set.of());

        assertThat(service.roleNamesHiddenFor(ORG_ID)).isEmpty();
        verify(roleRepository, never()).findByOrganizationId(any());
        verify(roleRepository, never()).findByIsSystemRoleTrueOrderByUpdatedAtDesc();
    }

    private static Role systemRole(long id, String name, Permission... permissions) {
        return Role.builder().id(id).name(name).isSystemRole(true)
                .permissions(new HashSet<>(Set.of(permissions))).build();
    }

    private static Permission permission(long id, String name, String resource) {
        return Permission.builder().id(id).name(name).resource(resource).action(name.substring(name.indexOf(':') + 1))
                .build();
    }

    private static Role customRole(long id, String name, Permission... permissions) {
        return Role.builder().id(id).name(name).organization(ORGANIZATION).isSystemRole(false)
                .permissions(new HashSet<>(Set.of(permissions))).build();
    }

    private static User user(Set<Permission> permissions) {
        return User.builder().id(7).organization(ORGANIZATION).active(true)
                .roles(new HashSet<>()).permissions(permissions).build();
    }
}
