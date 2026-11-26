// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.auth;

import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public record AuthenticatedUser(
        Long userId,
        String email,
        String organizationId,
        String organizationName,
        List<String> roles,
        List<String> permissions,
        String authMethod
) {

    public AuthenticatedUser {
        roles = List.copyOf(roles);
        permissions = List.copyOf(permissions);
    }

    public List<GrantedAuthority> authorities() {
        return java.util.stream.Stream.concat(
                        roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)),
                        permissions.stream().map(permission -> new SimpleGrantedAuthority("PERM_" + permission)))
                .map(GrantedAuthority.class::cast)
                .toList();
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /** True when the principal carries the named permission (e.g. {@code "integrations:view"}). */
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }
}
