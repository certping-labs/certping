// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.JwtClaims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * The permissions the current request's token carries: the same authorities
 * {@code @PreAuthorize("hasPermission(null, 'x')")} checks through {@link CustomPermissionEvaluator},
 * for the few checks that depend on request data and so cannot be an annotation.
 */
public final class CallerPermissions {

    private CallerPermissions() {
    }

    /**
     * The current caller's permission authorities ({@code resource:action}); role authorities
     * ({@code ROLE_*}) are left out.
     *
     * @return an immutable set; empty outside an authenticated request
     */
    public static Set<String> current() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getAuthorities() == null) {
            return Set.of();
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority != null && !authority.startsWith(JwtClaims.ROLE_PREFIX))
                .collect(Collectors.toUnmodifiableSet());
    }
}
