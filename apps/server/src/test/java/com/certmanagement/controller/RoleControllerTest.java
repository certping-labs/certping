// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.role.CreateRoleRequest;
import com.certmanagement.dto.role.AssignRolesRequest;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.RoleManagementService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RoleControllerTest {

    @Mock private RoleManagementService roleManagementService;

    @AfterEach
    void cleanupContext() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void getAllRoles_superAdminWithoutOrganizationIdUsesGlobalRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));

        controller.getAllRoles(null);

        verify(roleManagementService).getAllRoles();
    }

    @Test
    void getAllPermissions_superAdminWithoutOrganizationIdUsesGlobalRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));

        controller.getAllPermissions(null);

        verify(roleManagementService).getAllPermissions();
    }

    @Test
    void getPermissionsByResource_superAdminWithoutOrganizationIdUsesGlobalRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));

        controller.getPermissionsByResource("roles", null);

        verify(roleManagementService).getPermissionsByResource("roles");
    }

    @Test
    void getAllRoles_nonSuperWithoutOrganizationUsesNullOrganizationScopedRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("platform-reader", "n/a", List.of()));

        controller.getAllRoles(null);

        verify(roleManagementService).getAllRoles((Long) null);
    }

    @Test
    void getAllPermissions_nonSuperWithoutOrganizationUsesNullOrganizationScopedRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("platform-reader", "n/a", List.of()));

        controller.getAllPermissions(null);

        verify(roleManagementService).getAllPermissions((Long) null);
    }

    @Test
    void getPermissionsByResource_nonSuperWithoutOrganizationUsesNullOrganizationScopedRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("platform-reader", "n/a", List.of()));

        controller.getPermissionsByResource("roles", null);

        verify(roleManagementService).getPermissionsByResource("roles", null);
    }

    @Test
    void getRoleById_nonSuperWithoutOrganizationUsesNullOrganizationScopedRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("platform-reader", "n/a", List.of()));

        controller.getRoleById(42L, null);

        verify(roleManagementService).getRoleById(42L, null);
    }

    @Test
    void getRolePermissions_nonSuperWithoutOrganizationUsesNullOrganizationScopedRead() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("platform-reader", "n/a", List.of()));

        controller.getRolePermissions(42L, null);

        verify(roleManagementService).getRolePermissions(42L, null);
    }

    @Test
    void createRole_organizationCallerCannotOverrideOrganization() {
        RoleController controller = new RoleController(roleManagementService);
        Long jwtOrganizationId = 1L;
        Long otherOrganizationId = 2L;
        GatewayRequestContext.set(20, String.valueOf(jwtOrganizationId), "req-2", "organization-admin@acme.com");

        CreateRoleRequest request = CreateRoleRequest.builder()
                .name("OPS_VIEWER")
                .description("Ops viewer")
                .permissionNames(Set.of("users:view"))
                .build();

        assertThatThrownBy(() -> controller.createRole(request, otherOrganizationId))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("organizationId override");
    }

    @Test
    void deleteRole_usesOrganizationScopedSoftDeletePath() {
        RoleController controller = new RoleController(roleManagementService);
        Long jwtOrganizationId = 9L;
        Long roleId = 123L;
        GatewayRequestContext.set(20, String.valueOf(jwtOrganizationId), "req-2", "organization-admin@acme.com");

        controller.deleteRole(roleId, null);

        verify(roleManagementService).deleteRole(roleId, jwtOrganizationId);
    }

    @Test
    void assignRolesToUser_superAdminWithoutOrganizationIdUsesGlobalScope() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));
        AssignRolesRequest request = AssignRolesRequest.builder().roleIds(Set.of(1L, 2L)).build();

        controller.assignRolesToUser(7, request, null);

        verify(roleManagementService).assignRolesToUser(7, null, Set.of(1L, 2L));
    }

    @Test
    void getUserPermissions_superAdminWithoutOrganizationIdUsesGlobalScope() {
        RoleController controller = new RoleController(roleManagementService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));

        controller.getUserPermissions(7, null);

        verify(roleManagementService).getUserPermissions(7, null);
    }
}
