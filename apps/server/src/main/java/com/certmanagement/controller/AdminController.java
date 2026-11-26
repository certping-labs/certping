// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.auth.ChangePasswordRequest;
import com.certmanagement.dto.auth.CreateUserRequest;
import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.dto.auth.LocalLoginResponse;

import com.certmanagement.dto.user.UserDto;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.AdminUserService;
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

import java.util.Map;

import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;


import static com.certmanagement.security.Permissions.*;

/**
 * Controller for system administration: bootstrap, local login, and user creation.
 *
 * Flow:
 * 1. Startup bootstrap creates a hardcoded SUPER_ADMIN account.
 * 2. POST /api/v1/admin/login   — local username/password login; public.
 * 3. Admin creates organization via POST /api/v1/organizations.
 * 4. POST /api/v1/admin/users   — create additional local users; requires users:create.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Admin", description = "System administration and local auth APIs")
public class AdminController {

    private final AdminUserService adminUserService;
    private final OrganizationRepository organizationRepository;

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(AdminController.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }

    // ===== System Bootstrap Status =====

    @GetMapping(Paths.ADMIN_STATUS)
    @Operation(summary = "Check system status",
               description = "Returns whether any users exist (system initialized)")
    public ResponseEntity<Map<String, Object>> getSystemStatus() {
        boolean initialized = adminUserService.isSystemInitialized();
        return ResponseEntity.ok(Map.of(
                "initialized", initialized,
                "message", initialized
                        ? "System is initialized. Use POST /api/v1/admin/login."
                        : "System not initialized. Bootstrap SUPER_ADMIN user should be provisioned at startup."));
    }



    // ===== Local Auth Login (public) =====

    @PostMapping(Paths.ADMIN_LOGIN)
    @Operation(summary = "Local user login",
               description = "Authenticate with username and password. Returns JWT access token.")
    public ResponseEntity<LocalLoginResponse> login(@Valid @RequestBody LocalLoginRequest request) {
        contextLogger().info("Local login attempt");
        LocalLoginResponse response = adminUserService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    // ===== Protected: Change Password =====

    @PostMapping(Paths.ADMIN_CHANGE_PW)
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Change password",
               description = "Change the current user's local auth password.")
    public ResponseEntity<Void> changePassword(@Valid @RequestBody ChangePasswordRequest request,
                                               jakarta.servlet.http.HttpServletRequest httpRequest) {
        Integer userId = GatewayRequestContext.getUserId();
        if (userId == null) {
            throw new BadRequestException("Cannot resolve user identity from token");
        }
        contextLogger().info("Change password request");
        adminUserService.changePassword(userId, request, LocalAccountController.currentAccessToken(httpRequest));
        return ResponseEntity.noContent().build();
    }

    // ===== Protected: Create Local User =====

    @AuditFailure(value = AuditEventType.MEMBER_CREATED, organization = "#request.organizationId")
    @PostMapping(Paths.ADMIN_USERS)
    @PreAuthorize("hasPermission(null, '" + USERS_CREATE + "') or hasPermission(null, '" + USERS_MANAGE + "')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Create local user",
               description = "Create a new local (username/password) user. Requires users:create or users:manage.")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody CreateUserRequest request) {
        contextLogger().info("Creating local user");

        Long organizationId;
        if (OrgResolver.isSuperAdmin()) {
            organizationId = request.getOrganizationId();
            // A super admin scopes new members to an organization, EXCEPT when creating another
            // super admin — SUPER_ADMIN users are platform-level and must have no organization.
            if (organizationId == null && !adminUserService.targetsSuperAdminRole(request)) {
                throw new BadRequestException("organizationId is required in request payload for SUPER_ADMIN /api/v1/admin/users");
            }
        } else {
            String organizationIdStr = GatewayRequestContext.getOrganizationId();
            if (organizationIdStr == null || organizationIdStr.isBlank()) {
                throw new BadRequestException("Organization context is required in JWT for /api/v1/admin/users");
            }
            try {
                organizationId = Long.parseLong(organizationIdStr);
            } catch (IllegalArgumentException ex) {
                throw new BadRequestException("Invalid organizationId in JWT context");
            }
        }

        Organization organization = organizationId == null ? null
                : organizationRepository.findById(organizationId)
                        .orElseThrow(() -> new ResourceNotFoundException("Organization not found: " + organizationId));

        User created = adminUserService.createUserFromRequest(request, organization);

        UserDto dto = UserDto.builder()
                .id(created.getId())
                .email(created.getEmail())
                .username(created.getUsername())
                .displayName(created.getDisplayName())
                .active(created.getActive())
                .authMethod(created.getAuthMethod() != null ? created.getAuthMethod().name() : null)
                .roles(created.getRoleNames())
                .permissions(created.getPermissionNames())
                .mustChangePassword(created.getMustChangePassword())
                .organizationId(organization != null ? organization.getId() : null)
                .organizationName(organization != null ? organization.getName() : null)
                .build();

        contextLogger().info("Created local user successfully");
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }
}
