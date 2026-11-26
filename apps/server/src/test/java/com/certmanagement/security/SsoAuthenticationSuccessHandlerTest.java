// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.service.SsoAuthenticationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SsoAuthenticationSuccessHandlerTest {

    private static final String FRONTEND = "https://certping.example.com/sso/callback";

    @Mock private SsoAuthenticationService ssoAuthenticationService;
    @Mock private SsoLoginCodes ssoLoginCodes;

    @org.junit.jupiter.api.BeforeEach
    @org.junit.jupiter.api.AfterEach
    void clearRequestContext() {
        com.certmanagement.interceptor.RequestContextInterceptor.clearContext();
    }

    private AuthTokenResponse tokens() {
        return AuthTokenResponse.builder()
                .accessToken("access-tok").refreshToken("refresh-tok").expiresIn(3600L).build();
    }

    private OidcAuthenticationSuccessHandler oidcHandler() {
        OidcAuthenticationSuccessHandler h = new OidcAuthenticationSuccessHandler(ssoAuthenticationService,
                new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null), ssoLoginCodes);
        ReflectionTestUtils.setField(h, "frontendRedirectUrl", FRONTEND);
        return h;
    }

    @Test
    void oidcSuccess_redirectsWithTokens() throws Exception {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        when(token.getAuthorizedClientRegistrationId()).thenReturn("org-1-google-oidc");
        when(ssoAuthenticationService.processOidcAuthentication(eq(token), eq("org-1-google-oidc")))
                .thenReturn(tokens());
        when(ssoLoginCodes.issue(org.mockito.ArgumentMatchers.any())).thenReturn("one-time-code");

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/oauth2/code/org-1-google-oidc");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        oidcHandler().onAuthenticationSuccess(req, resp, token);

        assertThat(resp.getRedirectedUrl())
                .startsWith(FRONTEND)
                .isEqualTo(FRONTEND + "?code=one-time-code")
                .doesNotContain("access-tok")
                .doesNotContain("refresh-tok");
    }

    @Test
    void oidcSuccess_serviceThrows_redirectsWithError() throws Exception {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        when(token.getAuthorizedClientRegistrationId()).thenReturn("reg");
        when(ssoAuthenticationService.processOidcAuthentication(eq(token), eq("reg")))
                .thenThrow(new RuntimeException("provisioning failed"));

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/oauth2/code/reg");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        oidcHandler().onAuthenticationSuccess(req, resp, token);

        assertThat(resp.getRedirectedUrl())
                .startsWith(FRONTEND)
                .contains("error=authentication_failed")
                .as("an unexpected exception's text never reaches the redirect")
                .doesNotContain("provisioning");
        var query = SignInFailureRedirectTest.query(resp.getRedirectedUrl());
        assertThat(query.getFirst("message")).isEqualTo(SignInFailures.GENERIC_MESSAGE);
        assertThat(query).as("INTERNAL_ERROR is not a sign-in reason: no reason, the page shows its generic text")
                .doesNotContainKey("reason");
        assertThat(query.getFirst("ref")).as("the request id is still there to quote").startsWith("req-http-");
    }

    @Test
    void oidcSuccess_refusedAsMisconfigured_redirectsWithTheReasonAndTheRequestId() throws Exception {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        when(token.getAuthorizedClientRegistrationId()).thenReturn("reg");
        String[] idDuringSignIn = new String[2];
        when(ssoAuthenticationService.processOidcAuthentication(eq(token), eq("reg"))).thenAnswer(call -> {
            idDuringSignIn[0] = com.certmanagement.interceptor.RequestContextInterceptor.getCurrentRequestId();
            idDuringSignIn[1] = com.certmanagement.interceptor.RequestContextInterceptor.getCurrentCorrelationId();
            throw new SignInRefusedException(SignInFailures.SSO_MISCONFIGURED, null, "SSO configuration is disabled");
        });
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/oauth2/code/reg");
        req.addHeader("X-Request-ID", "gw-7f3a2c");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        oidcHandler().onAuthenticationSuccess(req, resp, token);

        var query = SignInFailureRedirectTest.query(resp.getRedirectedUrl());
        assertThat(query.getFirst("reason")).isEqualTo("SSO_MISCONFIGURED");
        assertThat(query.getFirst("message")).isEqualTo("SSO configuration is disabled");
        assertThat(query.getFirst("ref")).as("a minted id, as the audit row saw it")
                .startsWith("req-http-").isEqualTo(idDuringSignIn[0]);
        assertThat(idDuringSignIn[1]).as("the incoming id is only the correlation id").isEqualTo("gw-7f3a2c");
        assertThat(com.certmanagement.interceptor.RequestContextInterceptor.getCurrentRequestId())
                .as("the callback puts back what the thread held").isEqualTo("unknown");
    }

    @Test
    void oidcSuccess_memberNotProvisioned_redirectsWithTheReason() throws Exception {
        OAuth2AuthenticationToken token = org.mockito.Mockito.mock(OAuth2AuthenticationToken.class);
        when(token.getAuthorizedClientRegistrationId()).thenReturn("reg");
        when(ssoAuthenticationService.processOidcAuthentication(eq(token), eq("reg")))
                .thenThrow(new com.certmanagement.exception.SsoMemberNotProvisionedException("not provisioned"));
        MockHttpServletResponse resp = new MockHttpServletResponse();

        oidcHandler().onAuthenticationSuccess(new MockHttpServletRequest("GET", "/login/oauth2/code/reg"), resp, token);

        var query = SignInFailureRedirectTest.query(resp.getRedirectedUrl());
        assertThat(query.getFirst("reason")).isEqualTo("SSO_MEMBER_NOT_PROVISIONED");
        assertThat(query.getFirst("ref")).startsWith("req-http-");
    }
}
