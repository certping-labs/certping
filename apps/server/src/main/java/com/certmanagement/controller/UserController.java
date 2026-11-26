// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.dto.user.UserDto;
import com.certmanagement.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.certmanagement.constants.Paths;


import java.util.List;

import static com.certmanagement.security.Permissions.*;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping(Paths.USERS_ID)
    @PreAuthorize("hasPermission(null, '" + USERS_VIEW + "') or hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<UserDto> getUserById(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? userService.getUserById(id)
                        : userService.getUserByIdAndOrganization(id, effectiveOrganizationId));
    }

    @GetMapping(Paths.USERS_BASE)
    @PreAuthorize("hasPermission(null, '" + USERS_VIEW + "') or hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<List<UserDto>> getAllUsers(@RequestParam(required = false) Long organizationId) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? userService.getAllUsers()
                        : userService.getUsersByOrganization(effectiveOrganizationId));
    }

    // Organization-scoped endpoints
    @GetMapping(Paths.USERS_ORGANIZATION_BASE)
    @PreAuthorize("hasPermission(null, '" + USERS_VIEW + "') or hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<List<UserDto>> getUsersForOrganization(@RequestParam(required = false) Long organizationId) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? userService.getAllUsers()
                        : userService.getUsersByOrganization(effectiveOrganizationId));
    }

    @AuditFailure(value = AuditEventType.MEMBER_UPDATED, target = "#id", organization = "#organizationId")
    @PutMapping(Paths.USERS_ID)
    @PreAuthorize("hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<UserDto> updateUser(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId,
            @RequestBody UserDto dto) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? userService.updateUser(id, dto)
                        : userService.updateUserForOrganization(id, effectiveOrganizationId, dto));
    }

    @AuditFailure(value = AuditEventType.MEMBER_UPDATED, target = "#id", organization = "#organizationId")
    @PutMapping(Paths.USERS_ORGANIZATION_ID)
    @PreAuthorize("hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<UserDto> updateUserForOrganization(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId,
            @RequestBody UserDto dto) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        return ResponseEntity.ok(
                effectiveOrganizationId == null && OrgResolver.isSuperAdmin()
                        ? userService.updateUser(id, dto)
                        : userService.updateUserForOrganization(id, effectiveOrganizationId, dto));
    }

    @AuditFailure(value = AuditEventType.MEMBER_DELETED, target = "#id", organization = "#organizationId")
    @DeleteMapping(Paths.USERS_ID)
    @PreAuthorize("hasPermission(null, '" + USERS_DELETE + "') or hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<Void> deleteUser(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        if (effectiveOrganizationId == null && OrgResolver.isSuperAdmin()) {
            userService.deleteUser(id);
        } else {
            userService.deleteUserForOrganization(id, effectiveOrganizationId);
        }
        return ResponseEntity.noContent().build();
    }

    @AuditFailure(value = AuditEventType.MEMBER_DELETED, target = "#id", organization = "#organizationId")
    @DeleteMapping(Paths.USERS_ORGANIZATION_ID)
    @PreAuthorize("hasPermission(null, '" + USERS_DELETE + "') or hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<Void> deleteUserForOrganization(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        if (effectiveOrganizationId == null && OrgResolver.isSuperAdmin()) {
            userService.deleteUser(id);
        } else {
            userService.deleteUserForOrganization(id, effectiveOrganizationId);
        }
        return ResponseEntity.noContent().build();
    }

    @AuditFailure(value = AuditEventType.MEMBER_DISABLED, target = "#id", organization = "#organizationId")
    @PostMapping(Paths.USERS_DISABLE)
    @PreAuthorize("hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<Void> disableUser(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        if (effectiveOrganizationId == null && OrgResolver.isSuperAdmin()) {
            userService.disableUser(id);
        } else {
            userService.disableUserForOrganization(id, effectiveOrganizationId);
        }
        return ResponseEntity.noContent().build();
    }

    @AuditFailure(value = AuditEventType.MEMBER_DISABLED, target = "#id", organization = "#organizationId")
    @PostMapping(Paths.USERS_ORGANIZATION_DISABLE)
    @PreAuthorize("hasPermission(null, '" + USERS_MANAGE + "')")
    public ResponseEntity<Void> disableUserForOrganization(
            @PathVariable Integer id,
            @RequestParam(required = false) Long organizationId) {
        Long effectiveOrganizationId = OrgResolver.resolveOptional(organizationId);
        if (effectiveOrganizationId == null && OrgResolver.isSuperAdmin()) {
            userService.disableUser(id);
        } else {
            userService.disableUserForOrganization(id, effectiveOrganizationId);
        }
        return ResponseEntity.noContent().build();
    }
}
