// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.permission.PermissionDto;
import com.certmanagement.dto.role.AssignRolesRequest;
import com.certmanagement.dto.role.CreateRoleRequest;
import com.certmanagement.dto.role.RoleDto;
import com.certmanagement.dto.role.UpdateRolePermissionsRequest;
import com.certmanagement.dto.role.UpdateUserPermissionsRequest;

import com.certmanagement.service.RoleManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;

import static com.certmanagement.security.Permissions.*;

/**
 * Controller for role and permission management.
 */
@RestController
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Roles & Permissions", description = "Role and permission management APIs")
public class RoleController {

    private final RoleManagementService roleManagementService;

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(RoleController.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }

    // ===== Role Endpoints =====

    @GetMapping(Paths.ROLES_BASE)
    @PreAuthorize("hasPermission(null, '" + ROLES_VIEW + "')")
    @Operation(summary = "List all roles")
    public ResponseEntity<List<RoleDto>> getAllRoles(@RequestParam(required = false) Long organizationId) {
        contextLogger().info("Getting all roles");
        Long effectiveOrganizationId = OrgResolver.resolveOptionalAllowNullJwt(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? roleManagementService.getAllRoles()
                        : roleManagementService.getAllRoles(effectiveOrganizationId));
    }

    @GetMapping(Paths.ROLES_ID)
    @PreAuthorize("hasPermission(null, '" + ROLES_VIEW + "')")
    @Operation(summary = "Get role by ID")
    public ResponseEntity<RoleDto> getRoleById(
            @PathVariable Long id,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Getting role by ID: {}", id);
        Long effectiveOrganizationId = OrgResolver.resolveOptionalAllowNullJwt(organizationId);
        return ResponseEntity.ok(roleManagementService.getRoleById(id, effectiveOrganizationId));
    }

    @AuditFailure(value = AuditEventType.ROLE_CREATED, name = "#request.name", organization = "#organizationId")
    @PostMapping(Paths.ROLES_BASE)
    @PreAuthorize("hasPermission(null, '" + ROLES_CREATE + "')")
    @Operation(summary = "Create custom role")
    public ResponseEntity<RoleDto> createRole(
            @Valid @RequestBody CreateRoleRequest request,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Creating custom role: {}", request.getName());
        Long effectiveOrganizationId = OrgResolver.resolve(organizationId);
        RoleDto created = roleManagementService.createRole(request, effectiveOrganizationId);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @AuditFailure(value = AuditEventType.ROLE_DELETED, target = "#id", organization = "#organizationId")
    @DeleteMapping(Paths.ROLES_ID)
    @PreAuthorize("hasPermission(null, '" + ROLES_DELETE + "')")
    @Operation(summary = "Delete custom role", description = "System roles cannot be deleted.")
    public ResponseEntity<Void> deleteRole(
            @PathVariable Long id,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Deleting role: {}", id);
        Long effectiveOrganizationId = OrgResolver.resolve(organizationId);
        roleManagementService.deleteRole(id, effectiveOrganizationId);
        return ResponseEntity.noContent().build();
    }

    // ===== Permission-to-Role Mapping =====

    @GetMapping(Paths.ROLES_PERMISSIONS)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_VIEW + "')")
    @Operation(summary = "Get role permissions")
    public ResponseEntity<Set<PermissionDto>> getRolePermissions(
            @PathVariable Long id,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Getting permissions for role: {}", id);
        Long effectiveOrganizationId = OrgResolver.resolveOptionalAllowNullJwt(organizationId);
        return ResponseEntity.ok(roleManagementService.getRolePermissions(id, effectiveOrganizationId));
    }

    @AuditFailure(value = AuditEventType.ROLE_PERMISSIONS_CHANGED, target = "#id", organization = "#organizationId")
    @PutMapping(Paths.ROLES_PERMISSIONS)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_ASSIGN + "')")
    @Operation(summary = "Update role permissions", description = "Replaces all permissions for the role.")
    public ResponseEntity<RoleDto> updateRolePermissions(
            @PathVariable Long id,
            @Valid @RequestBody UpdateRolePermissionsRequest request,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Updating permissions for role: {}", id);
        Long effectiveOrganizationId = OrgResolver.resolve(organizationId);
        return ResponseEntity.ok(roleManagementService.updateRolePermissions(id, effectiveOrganizationId, request));
    }

    // ===== Role-to-User Assignment =====

    @AuditFailure(value = AuditEventType.MEMBER_ROLES_CHANGED, target = "#id", organization = "#organizationId")
    @PutMapping(Paths.USERS_ROLES)
    @PreAuthorize("hasPermission(null, '" + ROLES_ASSIGN + "')")
    @Operation(summary = "Assign roles to user", description = "Replaces all role assignments for the user.")
    public ResponseEntity<Void> assignRolesToUser(
            @PathVariable Integer id,
            @Valid @RequestBody AssignRolesRequest request,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Assigning {} roles to user: {}", request.getRoleIds().size(), id);
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        roleManagementService.assignRolesToUser(id, effectiveOrganizationId, request.getRoleIds());
        return ResponseEntity.ok().build();
    }

    // ===== Permission Endpoints =====

    @GetMapping(Paths.PERMISSIONS_BASE)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_VIEW + "')")
    @Operation(summary = "List all permissions")
    public ResponseEntity<List<PermissionDto>> getAllPermissions(@RequestParam(required = false) Long organizationId) {
        contextLogger().info("Getting all permissions");
        Long effectiveOrganizationId = OrgResolver.resolveOptionalAllowNullJwt(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? roleManagementService.getAllPermissions()
                        : roleManagementService.getAllPermissions(effectiveOrganizationId));
    }

    @GetMapping(Paths.PERMISSIONS_BY_RESOURCE)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_VIEW + "')")
    @Operation(summary = "List permissions by resource")
    public ResponseEntity<List<PermissionDto>> getPermissionsByResource(
            @PathVariable String resource,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Getting permissions for resource: {}", resource);
        Long effectiveOrganizationId = OrgResolver.resolveOptionalAllowNullJwt(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? roleManagementService.getPermissionsByResource(resource)
                        : roleManagementService.getPermissionsByResource(resource, effectiveOrganizationId));
    }

    // ===== User Permission Management =====

    @GetMapping(Paths.USERS_PERMISSIONS)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_VIEW + "')")
    @Operation(summary = "Get user's direct permissions")
    public ResponseEntity<Set<PermissionDto>> getUserPermissions(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Getting direct permissions for user: {}", id);
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(roleManagementService.getUserPermissions(id, effectiveOrganizationId));
    }

    @AuditFailure(value = AuditEventType.MEMBER_PERMISSIONS_CHANGED, target = "#id", organization = "#organizationId")
    @PutMapping(Paths.USERS_PERMISSIONS)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_ASSIGN + "')")
    @Operation(summary = "Set user permissions", description = "Replaces all direct permissions for the user.")
    public ResponseEntity<Set<PermissionDto>> setUserPermissions(
            @PathVariable Integer id,
            @Valid @RequestBody UpdateUserPermissionsRequest request,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Setting {} direct permissions for user: {}", request.getPermissionNames().size(), id);
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(roleManagementService.setUserPermissions(id, effectiveOrganizationId, request.getPermissionNames()));
    }

    @AuditFailure(value = AuditEventType.MEMBER_PERMISSIONS_CHANGED, target = "#id", organization = "#organizationId")
    @PostMapping(Paths.USERS_PERMISSIONS)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_ASSIGN + "')")
    @Operation(summary = "Add user permissions", description = "Adds permissions without removing existing ones.")
    public ResponseEntity<Set<PermissionDto>> addUserPermissions(
            @PathVariable Integer id,
            @Valid @RequestBody UpdateUserPermissionsRequest request,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Adding {} permissions to user: {}", request.getPermissionNames().size(), id);
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(roleManagementService.addUserPermissions(id, effectiveOrganizationId, request.getPermissionNames()));
    }

    @AuditFailure(value = AuditEventType.MEMBER_PERMISSIONS_CHANGED, target = "#id", organization = "#organizationId")
    @DeleteMapping(Paths.USERS_PERMISSIONS)
    @PreAuthorize("hasPermission(null, '" + PERMISSIONS_ASSIGN + "')")
    @Operation(summary = "Remove user permissions")
    public ResponseEntity<Set<PermissionDto>> removeUserPermissions(
            @PathVariable Integer id,
            @Valid @RequestBody UpdateUserPermissionsRequest request,
            @RequestParam(required = false) Long organizationId) {
        contextLogger().info("Removing {} permissions from user: {}", request.getPermissionNames().size(), id);
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(roleManagementService.removeUserPermissions(id, effectiveOrganizationId, request.getPermissionNames()));
    }
}
