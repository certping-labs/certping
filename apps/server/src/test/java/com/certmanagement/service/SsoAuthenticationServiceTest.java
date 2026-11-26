// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.oidc.PlatformOidcRegistration;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SsoAuthenticationServiceTest {

    @Mock private SsoAttributeExtractor attributeExtractor;
    @Mock private UserProvisioningService userProvisioningService;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private PlatformOidcRegistration platform;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private AuthAuditRecorder authAuditRecorder;

    @InjectMocks private SsoAuthenticationService service;

    private SsoUserInfo userInfo() {
        return SsoUserInfo.builder()
                .email("a@acme.com")
                .idpUserId("idp-1")
                .organizationDomain("acme.com")
                .displayName("Alice")
                .authMethod("OIDC")
                .build();
    }

    private Organization org() {
        return Organization.builder().id(42L).domain("acme.com").name("Acme").build();
    }

    private SsoConfig config() {
        return SsoConfig.builder().organization(org()).registrationId("reg-1").build();
    }

    private void provider(SsoConfig config) {
        when(platform.owns("reg-1")).thenReturn(true);
        when(platform.ssoConfig()).thenReturn(Optional.of(config));
    }

    private User user() {
        return User.builder().id(7).email("a@acme.com").build();
    }

    private void mockTokens() {
        when(jwtTokenProvider.generateAccessToken(any(), any(), any())).thenReturn("access");
        when(jwtTokenProvider.generateRefreshToken(any(User.class), any())).thenReturn("refresh");
        when(jwtTokenProvider.getExpirationTime()).thenReturn(1800L);
    }

    /** A token whose OIDC user the extractor turns into {@code info}. */
    private OAuth2AuthenticationToken oidcToken(SsoUserInfo info) {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        OidcUser oidcUser = org.mockito.Mockito.mock(OidcUser.class);
        when(token.getPrincipal()).thenReturn(oidcUser);
        when(attributeExtractor.extractFromOidc(eq(oidcUser), eq("reg-1"), any())).thenReturn(info);
        return token;
    }

    /** A token refused before its user is read. */
    private OAuth2AuthenticationToken unreadToken() {
        return org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
    }

    @Test
    void processOidc_success_returnsTokensAndAudits() {
        OAuth2AuthenticationToken token = oidcToken(userInfo());
        provider(config());
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());
        mockTokens();

        AuthTokenResponse resp = service.processOidcAuthentication(token, "reg-1");

        assertThat(resp.getAccessToken()).isEqualTo("access");
        assertThat(resp.getRefreshToken()).isEqualTo("refresh");
        assertThat(resp.getUserId()).isEqualTo(7);
        assertThat(resp.getOrganizationId()).isEqualTo(42L);
        verify(refreshTokenService).recordIssued(eq("refresh"), any(User.class), eq("SSO"));
        verify(authAuditRecorder).signedIn(any(), eq(AuthAuditRecorder.Method.OIDC), eq("reg-1"));
    }

    @Test
    void processOidc_refusesADisabledUser() {
        OAuth2AuthenticationToken token = oidcToken(userInfo());
        provider(config());
        User disabled = user();
        disabled.setActive(false);
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(disabled);

        assertThatThrownBy(() -> service.processOidcAuthentication(token, "reg-1"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessage("Account is disabled");
        verify(jwtTokenProvider, never()).generateAccessToken(any(), any(), any());
        verify(authAuditRecorder, never()).signedIn(any(), any(), any());
    }

    @Test
    void processOidc_refusesAUserOfASuspendedOrganization() {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        OidcUser oidcUser = org.mockito.Mockito.mock(OidcUser.class);
        when(token.getPrincipal()).thenReturn(oidcUser);
        when(attributeExtractor.extractFromOidc(eq(oidcUser), eq("reg-1"), any())).thenReturn(userInfo());
        SsoConfig cfg = config();
        cfg.getOrganization().setActive(false);
        provider(cfg);
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());

        assertThatThrownBy(() -> service.processOidcAuthentication(token, "reg-1"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessage("Organization is suspended or inactive");
        verify(jwtTokenProvider, never()).generateAccessToken(any(), any(), any());
    }

    @Test
    void processOidc_appliesAttributeMappingWhenConfigured() {
        SsoUserInfo info = userInfo();
        OAuth2AuthenticationToken token = oidcToken(info);
        SsoConfig cfg = SsoConfig.builder().organization(org()).registrationId("reg-1")
                .attributeMapping("{\"email\":\"mail\"}").build();
        provider(cfg);
        when(attributeExtractor.applyAttributeMapping(eq(info), anyString())).thenReturn(info);
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());
        mockTokens();

        service.processOidcAuthentication(token, "reg-1");

        verify(attributeExtractor).applyAttributeMapping(eq(info), eq("{\"email\":\"mail\"}"));
    }

    @Test
    void processOidc_withOidcUser_extractsFromOidc() {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        OidcUser oidcUser = org.mockito.Mockito.mock(OidcUser.class);
        when(token.getPrincipal()).thenReturn(oidcUser);
        when(attributeExtractor.extractFromOidc(eq(oidcUser), eq("reg-1"), any())).thenReturn(userInfo());
        provider(config());
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());
        mockTokens();

        AuthTokenResponse resp = service.processOidcAuthentication(token, "reg-1");

        assertThat(resp.getAccessToken()).isEqualTo("access");
        verify(attributeExtractor).extractFromOidc(eq(oidcUser), eq("reg-1"), any());
    }

    @Test
    void providerWithoutItsOrganization_isRefusedAsMisconfigured() {
        when(platform.owns("reg-1")).thenReturn(true);
        when(platform.ssoConfig()).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.processOidcAuthentication(unreadToken(), "reg-1"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("organization");
    }

    @Test
    void processOidc_withPlainOAuth2User_extractsFromOAuth2() {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        OAuth2User oauth2User = org.mockito.Mockito.mock(OAuth2User.class);
        when(token.getPrincipal()).thenReturn(oauth2User);
        when(attributeExtractor.extractFromOAuth2(eq(oauth2User), eq("reg-1"), any())).thenReturn(userInfo());
        provider(config());
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());
        mockTokens();

        service.processOidcAuthentication(token, "reg-1");

        verify(attributeExtractor).extractFromOAuth2(eq(oauth2User), eq("reg-1"), any());
    }

    /**
     * The bug this replaced: an organization that owns a second email domain could not log in,
     * because the tenant was resolved by matching the asserted email's domain against the single
     * organizations.domain column. The registration now decides the tenant, so the asserted
     * address is irrelevant to it.
     */
    @Test
    void emailDomainUnrelatedToOrganization_stillAuthenticates() {
        SsoUserInfo info = userInfo();
        info.setEmail("user@second-domain.com");
        info.setOrganizationDomain("second-domain.com");
        OAuth2AuthenticationToken token = oidcToken(info);
        provider(config());
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());
        mockTokens();

        AuthTokenResponse resp = service.processOidcAuthentication(token, "reg-1");

        assertThat(resp.getAccessToken()).isEqualTo("access");
        assertThat(resp.getOrganizationId()).isEqualTo(42L);
    }

    @Test
    void missingEmailDomain_doesNotBlockAuthentication() {
        SsoUserInfo info = userInfo();
        info.setOrganizationDomain(null);
        OAuth2AuthenticationToken token = oidcToken(info);
        provider(config());
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());
        mockTokens();

        assertThat(service.processOidcAuthentication(token, "reg-1").getOrganizationId())
                .isEqualTo(42L);
    }

    @Test
    void blankEmailFromIdp_throwsUnauthorizedRatherThanFailingAtFlush() {
        SsoUserInfo info = userInfo();
        info.setEmail(null);
        OAuth2AuthenticationToken token = oidcToken(info);
        provider(config());

        assertThatThrownBy(() -> service.processOidcAuthentication(token, "reg-1"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("email");
    }

    @Test
    void unknownRegistration_throwsUnauthorized() {
        assertThatThrownBy(() -> service.processOidcAuthentication(unreadToken(), "reg-1"))
                .isInstanceOf(UnauthorizedException.class);
        verify(platform, never()).ssoConfig();
    }

    /**
     * Guards the cross-tenant hole: an IdP admin can assert any email they like, so a login must
     * land in the organization that owns the registration it arrived on — never the one implied
     * by the asserted address. Previously the two were compared and a mismatch only logged a
     * warning while the email-derived organization won.
     */
    @Test
    void organizationAlwaysComesFromRegistration_notFromAssertedEmail() {
        SsoUserInfo info = userInfo();
        info.setEmail("attacker@acme.com");
        info.setOrganizationDomain("acme.com");
        OAuth2AuthenticationToken token = oidcToken(info);
        Organization registrationOwner = Organization.builder().id(999L).domain("other.com").name("Other").build();
        SsoConfig cfg = SsoConfig.builder().organization(registrationOwner).registrationId("reg-1").build();
        provider(cfg);
        when(userProvisioningService.findOrProvisionUser(any(), any(), any())).thenReturn(user());
        mockTokens();

        AuthTokenResponse resp = service.processOidcAuthentication(token, "reg-1");

        assertThat(resp.getOrganizationId()).isEqualTo(999L);
        verify(userProvisioningService).findOrProvisionUser(any(), eq(registrationOwner), eq(cfg));
    }
}
