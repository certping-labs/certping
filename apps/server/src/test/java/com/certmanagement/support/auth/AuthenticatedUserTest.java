// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

class AuthenticatedUserTest {

    private AuthenticatedUser user() {
        return new AuthenticatedUser(1L, "u@x.com", "10", "Acme",
                List.of("ADMIN", "USER"), List.of("alerts:view"), "PASSWORD");
    }

    @Test
    void authorities_prefixesRolesAndPermissions() {
        List<GrantedAuthority> authorities = user().authorities();
        assertThat(authorities).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER", "PERM_alerts:view");
    }

    @Test
    void hasRole_and_hasPermission() {
        AuthenticatedUser user = user();
        assertThat(user.hasRole("ADMIN")).isTrue();
        assertThat(user.hasRole("SUPERADMIN")).isFalse();
        assertThat(user.hasPermission("alerts:view")).isTrue();
        assertThat(user.hasPermission("alerts:delete")).isFalse();
    }

    @Test
    void compactConstructor_copiesLists_immutable() {
        AuthenticatedUser user = user();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> user.roles().add("X"))
                .isInstanceOf(UnsupportedOperationException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> user.permissions().add("Y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
