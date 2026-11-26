// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Role;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.security.Permissions;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

/**
 * Service for mapping IDP roles/groups to application roles.
 * 
 * Supports:
 * - Custom role claim names (OIDC: "roles", "groups")
 * - Role mapping configuration (IDP role -> App role)
 * - Role sync on login (IDP as source of truth)
 * - Default role assignment
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RoleMappingService {

    private final RoleRepository roleRepository;
    private final ObjectMapper objectMapper;

    /**
     * Get roles for a user based on IDP roles/groups and SSO config.
     * 
     * @param userInfo User info with IDP roles/groups
     * @param ssoConfig SSO configuration with role mapping
     * @return Set of application roles
     */
    public Set<Role> mapIdpRolesToAppRoles(SsoUserInfo userInfo, SsoConfig ssoConfig) {
        Long organizationId = ssoConfig != null && ssoConfig.getOrganization() != null
                ? ssoConfig.getOrganization().getId()
                : null;
        Set<Role> roles = new HashSet<>();
        
        // Get all IDP roles and groups
        Set<String> idpRolesAndGroups = new HashSet<>();
        if (userInfo.getRoles() != null) {
            idpRolesAndGroups.addAll(userInfo.getRoles());
        }
        if (userInfo.getGroups() != null) {
            idpRolesAndGroups.addAll(userInfo.getGroups());
        }

        contextLogger().debug("IDP roles/groups: {}", idpRolesAndGroups);

        // If role mapping is configured, map IDP roles to app roles
        if (ssoConfig.getRoleMapping() != null && !ssoConfig.getRoleMapping().isBlank()) {
            roles.addAll(applyRoleMapping(idpRolesAndGroups, ssoConfig.getRoleMapping(), organizationId));
        }

        // If no roles were mapped and we have a default role, use it
        if (roles.isEmpty()) {
            roles.addAll(getDefaultRole(ssoConfig));
        }

        contextLogger().info("Mapped roles: {} role(s) assigned", 
            roles.stream().map(Role::getName).collect(Collectors.toList()).size());

        return roles;
    }

    /**
     * Apply role mapping configuration.
     * 
     * Role mapping JSON format:
     * {
    *   "Admin": "ORGANIZATION_ADMIN",           // IDP role "Admin" -> App role "ORGANIZATION_ADMIN"
     *   "Certificate-Managers": "CERT_MANAGER", // IDP group -> App role
     *   "Viewers": "VIEWER"
     * }
     */
    private Set<Role> applyRoleMapping(Set<String> idpRolesAndGroups, String roleMappingJson, Long organizationId) {
        Set<Role> roles = new HashSet<>();

        try {
            Map<String, String> roleMapping = objectMapper.readValue(
                roleMappingJson, 
                new TypeReference<Map<String, String>>() {}
            );

            for (String idpRole : idpRolesAndGroups) {
                // Direct match
                if (roleMapping.containsKey(idpRole)) {
                    String appRoleName = roleMapping.get(idpRole);
                    findRoleByName(appRoleName, organizationId).ifPresent(roles::add);
                    continue;
                }

                // Case-insensitive match
                for (Map.Entry<String, String> entry : roleMapping.entrySet()) {
                    if (entry.getKey().equalsIgnoreCase(idpRole)) {
                        findRoleByName(entry.getValue(), organizationId).ifPresent(roles::add);
                        break;
                    }
                }
            }

            contextLogger().debug("Role mapping result: {} IDP roles -> {} app roles", 
                idpRolesAndGroups.size(), roles.size());

        } catch (Exception e) {
            contextLogger().error("Failed to parse role mapping JSON: {}", e.getMessage());
        }

        return roles;
    }

    /**
     * Get default role for a new user based on SSO config.
     */
    public Set<Role> getDefaultRole(SsoConfig ssoConfig) {
        Set<Role> roles = new HashSet<>();

        // Assign default role from SSO config if configured
        if (ssoConfig.getDefaultRole() != null) {
            // Defence in depth: a config saved before default roles were validated could still
            // carry SUPER_ADMIN. Never hand a platform-wide role to an IdP-provisioned user.
            if (isPlatformRole(ssoConfig.getDefaultRole().getName())) {
                contextLogger().error("SSO config {} has {} as its default role — refusing to assign it",
                        ssoConfig.getRegistrationId(), Permissions.ROLE_SUPER_ADMIN);
            } else {
                roles.add(ssoConfig.getDefaultRole());
                contextLogger().debug("Assigned default role: {}", ssoConfig.getDefaultRole().getName());
                return roles;
            }
        }

        // Fallback to VIEWER role
        roleRepository.findByNameAndOrganizationIsNull("VIEWER")
            .ifPresent(roles::add);
        contextLogger().debug("Assigned fallback VIEWER role");

        return roles;
    }

    /**
     * Resolve an application role named by the IdP role mapping.
     *
     * <p>Two rules matter here, because the input is controlled by the customer's IdP
     * administrator via the role-mapping JSON:
     *
     * <ul>
     *   <li>{@link Permissions#ROLE_SUPER_ADMIN} is platform-wide, not organization-scoped, so it
     *       must never be reachable from IdP-supplied input. A tenant admin mapping one of their
     *       own groups to it would otherwise mint platform administrators over every tenant.</li>
     *   <li>The fallback is scoped to the caller's organization: a custom role of another
     *       organization with the same name is never attached.</li>
     * </ul>
     */
    private Optional<Role> findRoleByName(String roleName, Long organizationId) {
        if (isPlatformRole(roleName)) {
            contextLogger().warn("Refusing to map IdP role/group to {} — platform-wide roles cannot "
                    + "be granted through SSO role mapping", Permissions.ROLE_SUPER_ADMIN);
            return Optional.empty();
        }

        // System roles (organization_id is null) are shared by every organization.
        Optional<Role> role = roleRepository.findByNameAndOrganizationIsNull(roleName);
        if (role.isPresent()) {
            return role;
        }

        // Otherwise only this organization's own roles are eligible.
        return organizationId == null
                ? Optional.empty()
                : roleRepository.findByNameAndOrganizationId(roleName, organizationId);
    }

    /** Roles that grant authority beyond a single organization and must never come from an IdP. */
    private boolean isPlatformRole(String roleName) {
        return Permissions.ROLE_SUPER_ADMIN.equalsIgnoreCase(roleName);
    }

    /**
     * Check if SSO config is set to map roles from IDP during initial provisioning.
     */
    public boolean shouldSyncRolesOnFirstLogin(SsoConfig ssoConfig) {
        return Boolean.TRUE.equals(ssoConfig.getSyncRolesOnFirstLogin());
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(RoleMappingService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
