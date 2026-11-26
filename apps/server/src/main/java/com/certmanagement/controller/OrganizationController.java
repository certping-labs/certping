// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.dto.organization.UpdateOrganizationRequest;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ForbiddenException;


import com.certmanagement.service.OrganizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import com.certmanagement.constants.Paths;

import java.util.List;

import static com.certmanagement.security.Permissions.*;

@RestController
@RequiredArgsConstructor
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Organization", description = "Organization management")
public class OrganizationController {

    private final OrganizationService organizationService;

    @AuditFailure(AuditEventType.ORGANIZATION_CREATED)
    @PostMapping(Paths.ORGANIZATIONS_BASE)
    @PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Create a new organization")
    public ResponseEntity<OrganizationDto> createOrganization(@Valid @RequestBody OrganizationDto dto) {
        OrganizationDto created = organizationService.createOrganization(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @GetMapping(Paths.ORGANIZATIONS_ID)
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_VIEW + "') or hasPermission(null, '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "Get organization by ID")
    public ResponseEntity<OrganizationDto> getOrganizationById(@PathVariable String id) {
        try {
            Long organizationId = OrgResolver.resolve(id);
            return ResponseEntity.ok(organizationService.getOrganizationById(organizationId));
        } catch (IllegalArgumentException ex) {
            String message = ex.getMessage() != null ? ex.getMessage() : "Invalid organization identifier";
            if (message.toLowerCase().contains("access") || message.toLowerCase().contains("forbidden")) {
                throw new ForbiddenException(message);
            }
            throw new BadRequestException(message);
        }
    }

    @GetMapping(Paths.ORGANIZATIONS_DOMAIN)
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_VIEW + "') or hasPermission(null, '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "Get organization by domain")
    public ResponseEntity<OrganizationDto> getOrganizationByDomain(@PathVariable String domain) {
        if (OrgResolver.isSuperAdmin()) {
            return ResponseEntity.ok(organizationService.getOrganizationByDomain(domain));
        }
        OrganizationDto organization = organizationService.getOrganizationById(OrgResolver.fromJwt());
        if (!organization.getDomain().equalsIgnoreCase(domain)) {
            throw new ForbiddenException("Access denied for requested organization domain");
        }
        return ResponseEntity.ok(organization);
    }

    @GetMapping(Paths.ORGANIZATIONS_SLUG)
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_VIEW + "') or hasPermission(null, '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "Get organization by slug")
    public ResponseEntity<OrganizationDto> getOrganizationBySlug(@PathVariable String slug) {
        if (OrgResolver.isSuperAdmin()) {
            return ResponseEntity.ok(organizationService.getOrganizationBySlug(slug));
        }
        OrganizationDto organization = organizationService.getOrganizationById(OrgResolver.fromJwt());
        if (!organization.getSlug().equalsIgnoreCase(slug)) {
            throw new ForbiddenException("Access denied for requested organization slug");
        }
        return ResponseEntity.ok(organization);
    }

    @GetMapping(Paths.ORGANIZATIONS_NAME)
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_VIEW + "') or hasPermission(null, '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "Get organization by name")
    public ResponseEntity<OrganizationDto> getOrganizationByName(@PathVariable String name) {
        if (OrgResolver.isSuperAdmin()) {
            return ResponseEntity.ok(organizationService.getOrganizationByName(name));
        }
        OrganizationDto organization = organizationService.getOrganizationById(OrgResolver.fromJwt());
        if (!organization.getName().equalsIgnoreCase(name)) {
            throw new ForbiddenException("Access denied for requested organization name");
        }
        return ResponseEntity.ok(organization);
    }

    @GetMapping(Paths.ORGANIZATIONS_BASE)
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "Get all organizations")
    public ResponseEntity<List<OrganizationDto>> getAllOrganizations() {
        if (OrgResolver.isSuperAdmin()) {
            return ResponseEntity.ok(organizationService.getAllOrganizations());
        }
        return ResponseEntity.ok(List.of(
                organizationService.getOrganizationById(OrgResolver.fromJwt())));
    }

    @AuditFailure(value = AuditEventType.ORGANIZATION_UPDATED, target = "#id", organization = "#id")
    @PutMapping(Paths.ORGANIZATIONS_ID)
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_MANAGE + "')"
            + " and @permissionGrantPolicy.mayAdministerOrganization(#id)")
    @Operation(summary = "Update organization details and active status")
    public ResponseEntity<OrganizationDto> updateOrganization(
            @PathVariable String id,
            @Valid @RequestBody UpdateOrganizationRequest request) {
        try {
            Long organizationId = OrgResolver.resolve(id);
            return ResponseEntity.ok(organizationService.updateOrganization(organizationId, request));
        } catch (IllegalArgumentException ex) {
            String message = ex.getMessage() != null ? ex.getMessage() : "Invalid organization identifier";
            if (message.toLowerCase().contains("access") || message.toLowerCase().contains("forbidden")) {
                throw new ForbiddenException(message);
            }
            throw new BadRequestException(message);
        }
    }

    @AuditFailure(value = AuditEventType.ORGANIZATION_DELETED, target = "#id", organization = "#id")
    @DeleteMapping(Paths.ORGANIZATIONS_ID)
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_MANAGE + "')"
            + " and @permissionGrantPolicy.mayAdministerOrganization(#id)")
    @Operation(summary = "Delete organization")
    public ResponseEntity<Void> deleteOrganization(@PathVariable String id) {
        try {
            Long organizationId = OrgResolver.resolve(id);
            organizationService.deleteOrganization(organizationId);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException ex) {
            String message = ex.getMessage() != null ? ex.getMessage() : "Invalid organization identifier";
            if (message.toLowerCase().contains("access") || message.toLowerCase().contains("forbidden")) {
                throw new ForbiddenException(message);
            }
            throw new BadRequestException(message);
        }
    }
}
