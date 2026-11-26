// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Organization;
import com.certmanagement.security.oidc.PlatformOidcRegistration;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.entity.User;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.ClientAddressResolver;
import com.certmanagement.security.ClientIpSource;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.OidcAuthenticationFailureHandler;
import com.certmanagement.security.OidcAuthenticationSuccessHandler;
import com.certmanagement.service.RefreshTokenService;
import com.certmanagement.service.SsoAttributeExtractor;
import com.certmanagement.service.SsoAuthenticationService;
import com.certmanagement.service.UserProvisioningService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.util.HashSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Single sign-on callbacks run in the security filter chain, outside the {@code /api/**} interceptor that
 * resolves the client for every other request. Their handlers resolve it with {@link ClientAddressResolver},
 * so the sign-in rows they write carry the client's address (never the client-controlled leftmost
 * {@code X-Forwarded-For} entry) and user agent, and the thread holds no address afterwards.
 */
class SsoCallbackClientAddressTest {

    private static final ClientAddressResolver RESOLVER =
            new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null);

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final AuthAuditRecorder authAudit = new AuthAuditRecorder(recorder, Clock.systemUTC());
    private MockHttpServletRequest callback;

    @BeforeEach
    void callbackThroughTraefik() {
        RequestContextInterceptor.clearContext();
        callback = new MockHttpServletRequest("GET", "/login/oauth2/code/org-42-oidc");
        callback.setRemoteAddr("10.244.1.17");
        callback.addHeader("X-Forwarded-For", "6.6.6.6, 198.51.100.20");
        callback.addHeader("User-Agent", "Mozilla/5.0 idp");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(callback));
    }

    @AfterEach
    void clear() {
        RequestContextInterceptor.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void aRejectedOidcTokensRowCarriesTheResolvedClient() throws Exception {
        OidcAuthenticationFailureHandler handler = new OidcAuthenticationFailureHandler(authAudit, RESOLVER);
        ReflectionTestUtils.setField(handler, "frontendRedirectUrl", "https://app.test/sso/callback");

        handler.onAuthenticationFailure(callback, new MockHttpServletResponse(),
                new OAuth2AuthenticationException(new OAuth2Error("invalid_id_token", "bad", null)));

        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordFailure(row.capture());
        assertThat(row.getValue().ipAddress()).as("the last proxy hop, never the leftmost entry")
                .isEqualTo("198.51.100.20");
        assertThat(row.getValue().userAgent()).isEqualTo("Mozilla/5.0 idp");
        assertThat(RequestContextInterceptor.getCurrentClientIp()).as("put back when the handler is done").isNull();
    }

    @Test
    void anOidcSignInsRowCarriesTheResolvedClient() throws Exception {
        PlatformOidcRegistration configs = mock(PlatformOidcRegistration.class);
        SsoAttributeExtractor extractor = mock(SsoAttributeExtractor.class);
        UserProvisioningService provisioning = mock(UserProvisioningService.class);
        JwtTokenProvider jwt = mock(JwtTokenProvider.class);
        Organization acme = Organization.builder().id(42L).name("Acme").build();
        when(configs.owns("reg")).thenReturn(true);
        when(configs.ssoConfig()).thenReturn(Optional.of(SsoConfig.builder().organization(acme)
                .registrationId("reg")
                .build()));
        when(extractor.extractFromOAuth2(any(), any(), any()))
                .thenReturn(SsoUserInfo.builder().email("alice@acme.test").authMethod("OIDC").build());
        when(provisioning.findOrProvisionUser(any(), any(), any())).thenReturn(User.builder().id(7)
                .email("alice@acme.test").active(true).organization(acme).roles(new HashSet<>()).build());
        when(jwt.generateAccessToken(any(), any(), any())).thenReturn("access");
        when(jwt.generateRefreshToken(any(User.class), any())).thenReturn("refresh");
        SsoAuthenticationService sso = new SsoAuthenticationService(extractor, provisioning, jwt, configs,
                mock(RefreshTokenService.class), authAudit);
        OidcAuthenticationSuccessHandler handler = new OidcAuthenticationSuccessHandler(sso, RESOLVER,
                org.mockito.Mockito.mock(com.certmanagement.security.SsoLoginCodes.class));
        ReflectionTestUtils.setField(handler, "frontendRedirectUrl", "https://app.test/sso/callback");
        OAuth2AuthenticationToken token = mock(OAuth2AuthenticationToken.class);
        when(token.getAuthorizedClientRegistrationId()).thenReturn("reg");
        when(token.getPrincipal()).thenReturn(mock(OAuth2User.class));

        handler.onAuthenticationSuccess(callback, new MockHttpServletResponse(), token);

        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordAsync(row.capture());
        assertThat(row.getValue().event()).isEqualTo("auth.signed_in");
        assertThat(row.getValue().ipAddress()).isEqualTo("198.51.100.20");
        assertThat(row.getValue().userAgent()).isEqualTo("Mozilla/5.0 idp");
        assertThat(RequestContextInterceptor.getCurrentClientIp()).isNull();
    }
}
