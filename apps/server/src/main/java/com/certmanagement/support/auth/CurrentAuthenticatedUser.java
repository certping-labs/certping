// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.auth;

import com.certmanagement.entity.Organization;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.support.common.ApiException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Bridges the support module to the server's authentication chain.
 *
 * <p>{@code JwtAuthenticationFilter} sets the SecurityContext principal to the
 * user's email string and stores userId/organizationId on {@link GatewayRequestContext}. This
 * helper reconstructs the {@link AuthenticatedUser} record that the support services were
 * originally written against, so service-layer code keeps working without modification.</p>
 *
 * <p>The organization name is looked up on demand via {@link OrganizationRepository} —
 * "Organisation" field reads from this. We cache nothing; the lookup is per request and rare.</p>
 */
@Component
public class CurrentAuthenticatedUser {

    private final OrganizationRepository organizationRepository;

    public CurrentAuthenticatedUser(OrganizationRepository organizationRepository) {
        this.organizationRepository = organizationRepository;
    }

    public AuthenticatedUser getRequired() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new ApiException(401, "AUTHENTICATION_REQUIRED", "Authentication is required");
        }

        Integer userIdInt = GatewayRequestContext.getUserId();
        String organizationIdStr = GatewayRequestContext.getOrganizationId();
        String email = GatewayRequestContext.getEmail();
        if (email == null && authentication.getPrincipal() instanceof String principalEmail) {
            email = principalEmail;
        }

        List<String> roles = new ArrayList<>();
        List<String> permissions = new ArrayList<>();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String name = authority.getAuthority();
            if (name.startsWith("ROLE_")) {
                roles.add(name.substring("ROLE_".length()));
            } else {
                permissions.add(name);
            }
        }

        Long userId = userIdInt != null ? userIdInt.longValue() : null;
        String organizationName = resolveOrganizationName(organizationIdStr);

        return new AuthenticatedUser(userId, email, organizationIdStr, organizationName,
                roles, permissions, null);
    }

    private String resolveOrganizationName(String organizationIdStr) {
        if (organizationIdStr == null || organizationIdStr.isBlank()) {
            return null;
        }
        try {
            Long orgId = Long.parseLong(organizationIdStr);
            return organizationRepository.findById(orgId).map(Organization::getName).orElse(null);
        } catch (NumberFormatException ex) {
            return null;
        }
    }
}
