// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class EntityCoverageTest {

    private Permission perm(String name) {
        return Permission.builder().id(1L).name(name).build();
    }

    private Role role(String name, Permission... perms) {
        return Role.builder().id(1L).name(name).permissions(new java.util.HashSet<>(Set.of(perms))).build();
    }

    @Test
    void userPermissionAndRoleAggregation() {
        Role r = role("ADMIN", perm("READ"), perm("WRITE"));
        User u = User.builder()
                .id(7)
                .email("a@b.com")
                .username("alice")
                .roles(new java.util.HashSet<>(Set.of(r)))
                .permissions(new java.util.HashSet<>(Set.of(perm("EXTRA"))))
                .build();

        assertThat(u.getPermissionNames()).containsExactly("EXTRA");
        assertThat(u.getEffectivePermissionNames()).containsExactlyInAnyOrder("READ", "WRITE", "EXTRA");
        assertThat(u.getRoleNames()).containsExactly("ADMIN");
    }

    @Test
    void userEffectivePermissionsHandlesNullRolePermissions() {
        Role nullPerms = Role.builder().id(2L).name("X").permissions(null).build();
        User u = User.builder().roles(new java.util.HashSet<>(Set.of(nullPerms))).build();
        assertThat(u.getEffectivePermissionNames()).isEmpty();
    }

    @Test
    void userAuthHelpers() {
        User u = new User();
        u.setAuthMethod(User.AuthMethod.LOCAL);
        assertThat(u.isLocalUser()).isTrue();
        u.setAuthMethod(User.AuthMethod.SSO);
        assertThat(u.isLocalUser()).isFalse();

        assertThat(u.isLocked()).isFalse();
        u.setLockedUntil(OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(10));
        assertThat(u.isLocked()).isTrue();
        u.setLockedUntil(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(10));
        assertThat(u.isLocked()).isFalse();
    }

    @Test
    void userLifecycleCallbacks() {
        User u = new User();
        u.setIsDeleted(null);
        u.onCreate();
        assertThat(u.getCreatedAt()).isNotNull();
        assertThat(u.getUpdatedAt()).isNotNull();
        assertThat(u.getIsDeleted()).isFalse();
        OffsetDateTime before = u.getUpdatedAt();
        u.onUpdate();
        assertThat(u.getUpdatedAt()).isAfterOrEqualTo(before);

        u.setDisplayName("Alice");
        u.setActive(true);
        u.setPasswordHash("h");
        u.setMustChangePassword(true);
        assertThat(u).isEqualTo(u);
        assertThat(u.toString()).contains("Alice");
    }

    @Test
    void discoveryStatusEnums() {
        for (DiscoveryConfigStatus s : DiscoveryConfigStatus.values()) {
            assertThat(DiscoveryConfigStatus.valueOf(s.name())).isSameAs(s);
        }
        for (DiscoveryScanStatus s : DiscoveryScanStatus.values()) {
            assertThat(DiscoveryScanStatus.valueOf(s.name())).isSameAs(s);
        }
        for (DiscoveryObservationStatus s : DiscoveryObservationStatus.values()) {
            assertThat(DiscoveryObservationStatus.valueOf(s.name())).isSameAs(s);
        }
        for (DiscoveryInventoryStatus s : DiscoveryInventoryStatus.values()) {
            assertThat(DiscoveryInventoryStatus.valueOf(s.name())).isSameAs(s);
        }
    }
}
