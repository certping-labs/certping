// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Extends {@link EntityCoverageTest} by exhaustively exercising every Lombok-generated
 * getter/setter (plus equals/hashCode/toString) for the large {@code @Data} entity
 * {@link User}, so all field accessor lines are executed.
 */
class EntityCoverageMoreTest {

    private static final OffsetDateTime NOW = OffsetDateTime.now(ZoneOffset.UTC);

    @Test
    void user_fullBuilderAndAllAccessors() {
        Organization org = Organization.builder().id(1L).name("Acme").build();
        Set<Role> roles = new HashSet<>(Set.of(Role.builder().id(1L).name("ADMIN").build()));
        Set<Permission> perms = new HashSet<>(Set.of(Permission.builder().id(1L).name("READ").build()));

        User u = User.builder()
                .id(5)
                .email("a@b.com")
                .organization(org)
                .idpUserId("idp-1")
                .username("alice")
                .passwordHash("hash")
                .displayName("Alice")
                .mustChangePassword(true)
                .failedLoginAttempts(2)
                .lockedUntil(NOW)
                .authMethod(User.AuthMethod.LOCAL)
                .active(true)
                .isDeleted(false)
                .lastLoginAt(NOW)
                .provisionedAt(NOW)
                .roles(roles)
                .permissions(perms)
                .createdAt(NOW)
                .updatedAt(NOW)
                .build();

        assertThat(u.getId()).isEqualTo(5);
        assertThat(u.getEmail()).isEqualTo("a@b.com");
        assertThat(u.getOrganization()).isSameAs(org);
        assertThat(u.getIdpUserId()).isEqualTo("idp-1");
        assertThat(u.getUsername()).isEqualTo("alice");
        assertThat(u.getPasswordHash()).isEqualTo("hash");
        assertThat(u.getDisplayName()).isEqualTo("Alice");
        assertThat(u.getMustChangePassword()).isTrue();
        assertThat(u.getFailedLoginAttempts()).isEqualTo(2);
        assertThat(u.getLockedUntil()).isEqualTo(NOW);
        assertThat(u.getAuthMethod()).isEqualTo(User.AuthMethod.LOCAL);
        assertThat(u.getActive()).isTrue();
        assertThat(u.getIsDeleted()).isFalse();
        assertThat(u.getLastLoginAt()).isEqualTo(NOW);
        assertThat(u.getProvisionedAt()).isEqualTo(NOW);
        assertThat(u.getRoles()).isEqualTo(roles);
        assertThat(u.getPermissions()).isEqualTo(perms);
        assertThat(u.getCreatedAt()).isEqualTo(NOW);
        assertThat(u.getUpdatedAt()).isEqualTo(NOW);
    }

    @Test
    void user_allSettersViaNoArgCtor() {
        User u = new User();
        u.setId(9);
        u.setEmail("z@z.com");
        u.setOrganization(Organization.builder().id(2L).build());
        u.setIdpUserId("idp-2");
        u.setUsername("bob");
        u.setPasswordHash("ph");
        u.setDisplayName("Bob");
        u.setMustChangePassword(false);
        u.setFailedLoginAttempts(0);
        u.setLockedUntil(NOW);
        u.setAuthMethod(User.AuthMethod.SSO);
        u.setActive(false);
        u.setIsDeleted(true);
        u.setLastLoginAt(NOW);
        u.setProvisionedAt(NOW);
        u.setRoles(new HashSet<>());
        u.setPermissions(new HashSet<>());
        u.setCreatedAt(NOW);
        u.setUpdatedAt(NOW);

        assertThat(u.getId()).isEqualTo(9);
        assertThat(u.getEmail()).isEqualTo("z@z.com");
        assertThat(u.getIsDeleted()).isTrue();
        assertThat(u.getActive()).isFalse();
    }

    @Test
    void user_equalsHashCodeToStringAndAllArgsCtor() {
        User a = new User(1, "e@e.com", null, "idp", "user", "pw", "Name",
                false, 0, null, null, User.AuthMethod.SSO, true, null, false, null, null,
                new HashSet<>(), new HashSet<>(), NOW, NOW);
        User b = new User(1, "e@e.com", null, "idp", "user", "pw", "Name",
                false, 0, null, null, User.AuthMethod.SSO, true, null, false, null, null,
                new HashSet<>(), new HashSet<>(), NOW, NOW);

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isEqualTo(a);
        assertThat(a).isNotEqualTo(null).isNotEqualTo("string");
        b.setEmail("different@e.com");
        assertThat(a).isNotEqualTo(b);
        assertThat(a.toString()).contains("Name");
        assertThat(a.canEqual(b)).isTrue();
    }

    @Test
    void user_authMethodEnumValues() {
        for (User.AuthMethod m : User.AuthMethod.values()) {
            assertThat(User.AuthMethod.valueOf(m.name())).isSameAs(m);
        }
    }
}
