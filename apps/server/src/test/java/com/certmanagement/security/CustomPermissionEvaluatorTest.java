// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CustomPermissionEvaluatorTest {

    private final CustomPermissionEvaluator evaluator = new CustomPermissionEvaluator();

    private Authentication authWith(String... authorities) {
        return new TestingAuthenticationToken("user", null,
                List.of(authorities).stream().map(SimpleGrantedAuthority::new).toList());
    }

    @Test
    void hasPermission_targetObject_trueWhenAuthorityPresent() {
        Authentication auth = authWith("certificate:read");
        assertThat(evaluator.hasPermission(auth, new Object(), "certificate:read")).isTrue();
    }

    @Test
    void hasPermission_targetObject_falseWhenAbsent() {
        Authentication auth = authWith("certificate:read");
        assertThat(evaluator.hasPermission(auth, new Object(), "certificate:delete")).isFalse();
    }

    @Test
    void hasPermission_targetObject_falseWhenAuthNull() {
        assertThat(evaluator.hasPermission(null, new Object(), "x")).isFalse();
    }

    @Test
    void hasPermission_targetObject_falseWhenPermissionNull() {
        Authentication auth = authWith("x");
        assertThat(evaluator.hasPermission(auth, new Object(), null)).isFalse();
    }

    @AfterEach
    void clearContext() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    private Authentication callerInOrg(Long organizationId, String... authorities) {
        GatewayRequestContext.set(1, organizationId == null ? null : String.valueOf(organizationId),
                "req-test", "user@example.com");
        Authentication authentication = authWith(authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

    @Test
    void hasPermission_organizationTarget_allowsTheCallersOwnOrganization() {
        Authentication caller = callerInOrg(42L, "organization:manage");
        assertThat(evaluator.hasPermission(caller, 42L, "ORGANIZATION", "organization:manage")).isTrue();
    }

    /**
     * The reason this evaluator exists. Every organization admin holds organization:manage for
     * their own tenant, so the authority alone must not authorise naming someone else's id.
     */
    @Test
    void hasPermission_organizationTarget_deniesAnotherOrganization() {
        Authentication caller = callerInOrg(42L, "organization:manage");
        assertThat(evaluator.hasPermission(caller, 7L, "ORGANIZATION", "organization:manage")).isFalse();
    }

    /** Super admins carry no organization claim, so this is the shape that actually reaches prod. */
    @Test
    void hasPermission_organizationTarget_allowsSuperAdminWithNoOrganizationOfTheirOwn() {
        Authentication caller = callerInOrg(null, "organization:manage", "ROLE_SUPER_ADMIN");
        assertThat(evaluator.hasPermission(caller, 7L, "ORGANIZATION", "organization:manage")).isTrue();
    }

    /** No organization in the token and not a super admin: nothing to compare against, so deny. */
    @Test
    void hasPermission_organizationTarget_deniesACallerWithNoOrganizationContext() {
        Authentication caller = callerInOrg(null, "organization:manage");
        assertThat(evaluator.hasPermission(caller, 7L, "ORGANIZATION", "organization:manage")).isFalse();
    }

    @Test
    void hasPermission_organizationTarget_deniesWhenTheAuthorityIsMissing() {
        Authentication caller = callerInOrg(42L, "organization:view");
        assertThat(evaluator.hasPermission(caller, 42L, "ORGANIZATION", "organization:manage")).isFalse();
    }

    @Test
    void hasPermission_organizationTarget_deniesAnUnparseableOrNullId() {
        Authentication caller = callerInOrg(42L, "organization:manage");
        assertThat(evaluator.hasPermission(caller, "not-a-number", "ORGANIZATION", "organization:manage")).isFalse();
        assertThat(evaluator.hasPermission(caller, null, "ORGANIZATION", "organization:manage")).isFalse();
        assertThat(evaluator.hasPermission(caller, "99999999999999999999", "ORGANIZATION", "organization:manage")).isFalse();
    }

    /** No object-level rule exists for other target types, so they are denied rather than waved through. */
    @Test
    void hasPermission_unknownTargetType_isDenied() {
        Authentication auth = authWith("widget:manage");
        assertThat(evaluator.hasPermission(auth, "123", "Widget", "widget:manage")).isFalse();
    }

    @Test
    void hasPermission_targetIdType_falseWhenAbsent() {
        Authentication auth = authWith("widget:view");
        assertThat(evaluator.hasPermission(auth, "123", "Widget", "widget:manage")).isFalse();
    }

    @Test
    void hasPermission_targetIdType_falseWhenAuthNull() {
        assertThat(evaluator.hasPermission(null, "123", "Widget", "widget:manage")).isFalse();
    }

    @Test
    void hasPermission_targetIdType_falseWhenPermissionNull() {
        Authentication auth = authWith("x");
        assertThat(evaluator.hasPermission(auth, "123", "Widget", null)).isFalse();
    }
}
