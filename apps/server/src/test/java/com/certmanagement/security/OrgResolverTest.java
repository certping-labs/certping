// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for org-scope enforcement rules in OrgResolver.
 *
 * Rule:
 *  - Non-super-admin: JWT org is the only allowed scope; any override to a different org throws.
 *  - Super-admin (resolve): must supply an explicit orgId; null throws.
 *  - Super-admin (resolveOptional): may pass null (global) or an explicit orgId.
 */
class OrgResolverTest {

    private static final Long JWT_ORG_ID = 42L;

    @BeforeEach
    void setJwtContext() {
        GatewayRequestContext.set(101, String.valueOf(JWT_ORG_ID), "req-scope-test", "user@test.com");
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void cleanup() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    // ------------------------------------------------------------------ //
    //  resolveEffectiveOrganizationId — non-super-admin
    // ------------------------------------------------------------------ //

    @Nested
    class ResolveEffective_NonSuperAdmin {

        @Test
        void noOverride_returnsJwtOrg() {
            Long resolved = OrgResolver.resolve((Long) null);
            assertThat(resolved).isEqualTo(JWT_ORG_ID);
        }

        @Test
        void matchingOverride_returnsJwtOrg() {
            Long resolved = OrgResolver.resolve(JWT_ORG_ID);
            assertThat(resolved).isEqualTo(JWT_ORG_ID);
        }

        @Test
        void differentOrgOverride_throwsAccessDenied() {
            assertThatThrownBy(() -> OrgResolver.resolve(99L))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("organizationId override is not allowed");
        }
    }

    // ------------------------------------------------------------------ //
    //  resolveEffectiveOrganizationId — super-admin
    // ------------------------------------------------------------------ //

    @Nested
    class ResolveEffective_SuperAdmin {

        @BeforeEach
        void setSuperAdminContext() {
            SecurityContextHolder.getContext().setAuthentication(
                    new TestingAuthenticationToken("admin", null,
                            List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
        }

        @Test
        void withExplicitOrgId_returnsIt() {
            Long resolved = OrgResolver.resolve(7L);
            assertThat(resolved).isEqualTo(7L);
        }

        @Test
        void withNullOrgId_andNoWorkingOrganization_throwsBadRequest() {
            GatewayRequestContext.clear();
            assertThatThrownBy(() -> OrgResolver.resolve((Long) null))
                    .isInstanceOf(BadRequestException.class)
                    .hasMessageContaining("organizationId is required for SUPER_ADMIN");
        }

        @Test
        void withNullOrgId_fallsBackToTheWorkingOrganizationInTheToken() {
            GatewayRequestContext.set(1, "42", "req", "admin@example.com");
            try {
                assertThat(OrgResolver.resolve((Long) null)).isEqualTo(42L);
                assertThat(OrgResolver.resolve(7L)).as("an explicit organization still wins").isEqualTo(7L);
            } finally {
                GatewayRequestContext.clear();
            }
        }
    }

    // ------------------------------------------------------------------ //
    //  resolveOptionalOrganizationIdForUserOps — non-super-admin
    // ------------------------------------------------------------------ //

    @Nested
    class ResolveOptional_NonSuperAdmin {

        @Test
        void noOverride_returnsJwtOrg() {
            Long resolved = OrgResolver.resolveOptional(null);
            assertThat(resolved).isEqualTo(JWT_ORG_ID);
        }

        @Test
        void matchingOverride_returnsJwtOrg() {
            Long resolved = OrgResolver.resolveOptional(JWT_ORG_ID);
            assertThat(resolved).isEqualTo(JWT_ORG_ID);
        }

        @Test
        void differentOrgOverride_throwsAccessDenied() {
            assertThatThrownBy(() -> OrgResolver.resolveOptional(99L))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("organizationId override is not allowed");
        }
    }

    // ------------------------------------------------------------------ //
    //  resolveOptionalOrganizationIdForUserOps — super-admin
    // ------------------------------------------------------------------ //

    @Nested
    class ResolveOptional_SuperAdmin {

        @BeforeEach
        void setSuperAdminContext() {
            SecurityContextHolder.getContext().setAuthentication(
                    new TestingAuthenticationToken("admin", null,
                            List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
        }

        @Test
        void withExplicitOrgId_returnsIt() {
            Long resolved = OrgResolver.resolveOptional(7L);
            assertThat(resolved).isEqualTo(7L);
        }

        @Test
        void withNullOrgId_returnsNull() {
            Long resolved = OrgResolver.resolveOptional(null);
            assertThat(resolved).isNull();
        }
    }
}
