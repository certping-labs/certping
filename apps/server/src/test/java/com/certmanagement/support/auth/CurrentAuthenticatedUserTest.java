// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.certmanagement.entity.Organization;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.support.common.ApiException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class CurrentAuthenticatedUserTest {

    private OrganizationRepository organizationRepository;
    private CurrentAuthenticatedUser current;

    @BeforeEach
    void setUp() {
        organizationRepository = mock(OrganizationRepository.class);
        current = new CurrentAuthenticatedUser(organizationRepository);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
    }

    private void authenticate(String principal) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                principal, "creds",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("alerts:view")));
        SecurityContextHolder.getContext().setAuthentication(token);
    }

    @Test
    void getRequired_noAuthentication_throws401() {
        SecurityContextHolder.clearContext();
        ApiException ex = catchThrowableOfType(() -> current.getRequired(), ApiException.class);
        assertThat(ex.status()).isEqualTo(401);
        assertThat(ex.code()).isEqualTo("AUTHENTICATION_REQUIRED");
    }

    @Test
    void getRequired_anonymous_throws401() {
        AnonymousAuthenticationToken anon = new AnonymousAuthenticationToken(
                "key", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
        SecurityContextHolder.getContext().setAuthentication(anon);
        ApiException ex = catchThrowableOfType(() -> current.getRequired(), ApiException.class);
        assertThat(ex.status()).isEqualTo(401);
    }

    @Test
    void getRequired_resolvesUserRolesPermissionsAndOrgName() {
        authenticate("jane@example.com");
        GatewayRequestContext.set(42, "100", "req-1", "jane@example.com");
        Organization org = mock(Organization.class);
        lenient().when(org.getName()).thenReturn("Acme Inc");
        when(organizationRepository.findById(100L)).thenReturn(Optional.of(org));

        AuthenticatedUser user = current.getRequired();

        assertThat(user.userId()).isEqualTo(42L);
        assertThat(user.email()).isEqualTo("jane@example.com");
        assertThat(user.organizationId()).isEqualTo("100");
        assertThat(user.organizationName()).isEqualTo("Acme Inc");
        assertThat(user.roles()).contains("ADMIN");
        assertThat(user.permissions()).contains("alerts:view");
    }

    @Test
    void getRequired_emailFallsBackToPrincipal() {
        authenticate("principal@example.com");
        GatewayRequestContext.set(7, "100", "req-1", null);
        Organization org = mock(Organization.class);
        lenient().when(org.getName()).thenReturn("Org");
        when(organizationRepository.findById(100L)).thenReturn(Optional.of(org));

        AuthenticatedUser user = current.getRequired();
        assertThat(user.email()).isEqualTo("principal@example.com");
    }

    @Test
    void getRequired_blankOrgId_nullOrgName() {
        authenticate("jane@example.com");
        GatewayRequestContext.set(7, null, "req-1", "jane@example.com");

        AuthenticatedUser user = current.getRequired();
        assertThat(user.organizationName()).isNull();
        assertThat(user.userId()).isEqualTo(7L);
    }

    @Test
    void getRequired_nonNumericOrgId_nullOrgName() {
        authenticate("jane@example.com");
        GatewayRequestContext.set(7, "abc", "req-1", "jane@example.com");

        AuthenticatedUser user = current.getRequired();
        assertThat(user.organizationName()).isNull();
        assertThat(user.organizationId()).isEqualTo("abc");
    }

    @Test
    void getRequired_orgNotFound_nullOrgName() {
        authenticate("jane@example.com");
        GatewayRequestContext.set(7, "100", "req-1", "jane@example.com");
        when(organizationRepository.findById(100L)).thenReturn(Optional.empty());

        AuthenticatedUser user = current.getRequired();
        assertThat(user.organizationName()).isNull();
    }
}
