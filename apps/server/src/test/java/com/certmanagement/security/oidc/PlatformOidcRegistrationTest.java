// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security.oidc;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PlatformOidcRegistrationTest {

    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final RoleRepository roles = mock(RoleRepository.class);
    private PlatformOidcProperties props;
    private PlatformOidcRegistration registration;

    @BeforeEach
    void setUp() {
        props = new PlatformOidcProperties();
        props.setIssuerUri("https://idp.example.com/realms/acme");
        props.setClientId("certping");
        props.setClientSecret("s3cret");
        props.setOrganization("acme");
        registration = new PlatformOidcRegistration(props, organizations, roles);
    }

    @Test
    void configuredOnlyWhenAllFourValuesAreSet() {
        assertThat(registration.configured()).isTrue();
        assertThat(registration.owns("sso")).isTrue();
        assertThat(registration.owns("org-1-okta-oidc")).isFalse();

        props.setClientSecret(" ");
        assertThat(registration.configured()).isFalse();
        assertThat(registration.owns("sso")).isFalse();
        assertThat(registration.clientRegistration()).isNull();
        assertThat(registration.ssoConfig()).isEmpty();
    }

    @Test
    void ssoConfigIsBuiltFromTheEnvironmentWithGroupMappingOff() {
        Organization acme = Organization.builder().id(5L).slug("acme").name("Acme").build();
        Role analyst = Role.builder().id(3L).name("SECURITY_ANALYST").build();
        when(organizations.findBySlug("acme")).thenReturn(Optional.of(acme));
        when(roles.findByNameAndOrganizationIsNull("SECURITY_ANALYST")).thenReturn(Optional.of(analyst));
        props.setDefaultRole("security_analyst");
        props.setAutoProvision(false);
        props.setScopes("profile email groups");

        SsoConfig config = registration.ssoConfig().orElseThrow();

        assertThat(config.getOrganization()).isSameAs(acme);
        assertThat(config.getRegistrationId()).isEqualTo("sso");
        assertThat(config.getSyncRolesOnFirstLogin()).isFalse();
        assertThat(config.getAutoProvisionEnabled()).isFalse();
        assertThat(config.getDefaultRole()).isSameAs(analyst);
        assertThat(registration.scopes()).containsExactly("openid", "profile", "email", "groups");
        assertThat(config.getAttributeMapping()).isNull();
    }

    @Test
    void organizationCanBeGivenByIdAndAnUnknownOneRefusesSignIn() {
        props.setOrganization("7");
        Organization byId = Organization.builder().id(7L).slug("seven").build();
        when(organizations.findById(7L)).thenReturn(Optional.of(byId));
        assertThat(registration.ssoConfig().orElseThrow().getOrganization()).isSameAs(byId);

        props.setOrganization("nobody");
        when(organizations.findBySlug("nobody")).thenReturn(Optional.empty());
        assertThat(registration.ssoConfig()).isEmpty();
    }

    @Test
    void superAdminAndUnknownDefaultRolesFallBackToViewer() {
        props.setDefaultRole("SUPER_ADMIN");
        assertThat(registration.defaultRole()).isEmpty();
        verify(roles, never()).findByNameAndOrganizationIsNull("SUPER_ADMIN");

        props.setDefaultRole("JANITOR");
        when(roles.findByNameAndOrganizationIsNull("JANITOR")).thenReturn(Optional.empty());
        assertThat(registration.defaultRole()).isEmpty();
    }

    @Test
    void theChainIsBuiltOnlyForTheWholeProvider() {
        PlatformOidcProperties.Configured condition = new PlatformOidcProperties.Configured();
        org.springframework.context.annotation.ConditionContext context =
                mock(org.springframework.context.annotation.ConditionContext.class);
        MockEnvironment env = new MockEnvironment();
        when(context.getEnvironment()).thenReturn(env);

        assertThat(condition.matches(context, null)).isFalse();
        env.setProperty("certping.oidc.issuer-uri", "https://idp.example.com");
        env.setProperty("certping.oidc.client-id", "certping");
        env.setProperty("certping.oidc.client-secret", "x");
        assertThat(condition.matches(context, null)).as("organization missing").isFalse();
        env.setProperty("certping.oidc.organization", "acme");
        assertThat(condition.matches(context, null)).isTrue();

        env.setProperty("certping.oidc.client-secret", " ");
        assertThat(condition.matches(context, null)).as("blank secret").isFalse();

        when(context.getEnvironment())
                .thenReturn(new MockEnvironment().withProperty("spring.security.oauth2.enabled", "true"));
        assertThat(condition.matches(context, null)).as("the old flag alone").isFalse();
    }
}
