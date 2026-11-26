// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.JwtClaims;
import com.certmanagement.constants.Paths;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.service.RefreshTokenService;
import com.certmanagement.service.audit.AccessAuditRecorder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * Lets the Platform Super Admin pick the organization they work in. The platform role is global, but
 * every certificate page resolves its organization from the session, so a super admin with none sees
 * only the platform pages. Choosing one sets {@code users.organization_id} and answers with new tokens
 * that carry it; the old refresh token names the old organization, so the refresh endpoint refuses it. The choice can be changed any
 * time and is audited in the organization's trail.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
@Tag(name = "Admin", description = "System administration and local auth APIs")
@SecurityRequirement(name = "bearer-jwt")
public class WorkingOrganizationController {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final RoleRepository roleRepository;
    private final AccessAuditRecorder accessAudit;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    public record WorkingOrganizationRequest(@NotNull Long organizationId) {
    }

    @PutMapping(Paths.ADMIN_ME_ORGANIZATION)
    @Transactional
    @Operation(summary = "Choose the organization the signed-in super admin works in",
            description = "Sets the account's organization and returns a new token pair that carries it.")
    public ResponseEntity<Map<String, Object>> choose(@RequestBody WorkingOrganizationRequest request) {
        Integer userId = GatewayRequestContext.getUserId();
        if (userId == null) {
            throw new BadRequestException("Cannot resolve user identity from token");
        }
        if (request == null || request.organizationId() == null) {
            throw new BadRequestException("organizationId is required");
        }
        Organization organization = organizationRepository.findById(request.organizationId())
                .filter(org -> !Boolean.TRUE.equals(org.getIsDeleted()))
                .orElseThrow(() -> new ResourceNotFoundException("Organization not found"));
        if (!Boolean.TRUE.equals(organization.getActive())) {
            throw new BadRequestException("The organization is disabled");
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        Long before = user.getOrganization() == null ? null : user.getOrganization().getId();
        if (!organization.getId().equals(before)) {
            user.setOrganization(organization);
            // The platform role has no certificate permissions; administer the organization worked in.
            roleRepository.findByNameAndOrganizationIsNull("ORGANIZATION_ADMIN")
                    .ifPresent(role -> user.getRoles().add(role));
            userRepository.save(user);
            accessAudit.memberOrganizationChanged(user);
            log.info("Super admin {} now works in organization {}", userId, organization.getId());
        }
        String authMethod = user.getAuthMethod() != null ? user.getAuthMethod().name() : JwtClaims.AUTH_METHOD_LOCAL;
        String accessToken = jwtTokenProvider.generateAccessToken(user, organization, authMethod);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user, organization);
        refreshTokenService.recordIssued(refreshToken, user, authMethod);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("organizationId", organization.getId());
        body.put("organizationName", organization.getName() == null ? "" : organization.getName());
        body.put("accessToken", accessToken);
        body.put("refreshToken", refreshToken);
        body.put("tokenType", JwtClaims.BEARER_TYPE);
        body.put("expiresIn", jwtTokenProvider.getExpirationTime());
        body.put("userId", user.getId());
        body.put("email", user.getEmail());
        body.put("roles", user.getRoleNames());
        body.put("permissions", user.getEffectivePermissionNames());
        return ResponseEntity.ok(body);
    }
}
