// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.JwtClaims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;

/**
 * Permission evaluator backing {@code @PreAuthorize("hasPermission(...)")}.
 *
 * <p>Two forms are supported. {@code hasPermission(null, 'some:permission')} is a plain authority
 * check. {@code hasPermission(#orgId, 'ORGANIZATION', 'some:permission')} additionally requires
 * that the caller may act on that organization — the authority alone is not enough, because every
 * organization admin holds the same authority for their own tenant.
 */
@Component
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private static final String ORGANIZATION_TARGET = "ORGANIZATION";

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || permission == null) {
            return false;
        }
        return hasAuthority(authentication.getAuthorities(), permission.toString());
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId,
                                 String targetType, Object permission) {
        if (authentication == null || permission == null) {
            return false;
        }
        if (!hasAuthority(authentication.getAuthorities(), permission.toString())) {
            return false;
        }
        if (!ORGANIZATION_TARGET.equals(targetType)) {
            // Deny rather than fall through to the authority-only check. Falling through is what
            // this method used to do, which made every object-level @PreAuthorize in the codebase
            // tenant-blind: any organization admin could name another organization's id.
            log.warn("Denying object-level permission check: no rule for targetType={}", targetType);
            return false;
        }
        return mayActOnOrganization(authentication, targetId);
    }

    /**
     * Super admins may name any organization; everyone else only the one in their own token, which
     * {@link OrgResolver} reads from the request context so this stays the rule the services apply.
     * The super-admin test reads the {@code Authentication} this evaluator was handed rather than
     * the holder — that is what a {@code PermissionEvaluator} is given, and it is the only thing
     * that differs if the evaluator is ever called outside {@code @PreAuthorize}.
     */
    private boolean mayActOnOrganization(Authentication authentication, Serializable targetId) {
        Long requested = OrgResolver.toOrganizationId(targetId);
        if (requested == null) {
            return false;
        }
        if (hasAuthority(authentication.getAuthorities(), JwtClaims.ROLE_PREFIX + Permissions.ROLE_SUPER_ADMIN)) {
            return true;
        }
        try {
            return requested.equals(OrgResolver.fromJwt());
        } catch (AccessDeniedException denied) {
            log.warn("Denying request for organizationId={} with no usable organization context: {}",
                    requested, denied.getMessage());
            return false;
        }
    }

    private boolean hasAuthority(Collection<? extends GrantedAuthority> authorities, String permission) {
        boolean hasPermission = authorities.stream()
            .anyMatch(a -> a.getAuthority().equals(permission));

        log.debug("Permission check for '{}': {}", permission, hasPermission);
        return hasPermission;
    }
}
