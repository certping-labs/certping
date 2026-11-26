// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.service.audit.AuthAuditRecorder;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class SsoAuthenticationFailureHandlerTest {

    private static final String FRONTEND = "https://certping.example.com/sso/callback";

    @org.junit.jupiter.api.BeforeEach
    @org.junit.jupiter.api.AfterEach
    void clearRequestContext() {
        com.certmanagement.interceptor.RequestContextInterceptor.clearContext();
    }

    private OidcAuthenticationFailureHandler oidcHandler() {
        OidcAuthenticationFailureHandler h = new OidcAuthenticationFailureHandler(org.mockito.Mockito.mock(AuthAuditRecorder.class),
                new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null));
        ReflectionTestUtils.setField(h, "frontendRedirectUrl", FRONTEND);
        return h;
    }

    @Test
    void oidcFailure_redirectsWithErrorAndEvictsSession() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/oauth2/code/org-1-google-oidc");
        MockHttpSession session = new MockHttpSession();
        req.setSession(session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        oidcHandler().onAuthenticationFailure(req, resp, new BadCredentialsException("oidc failed"));

        assertThat(resp.getRedirectedUrl())
                .startsWith(FRONTEND)
                .contains("error=authentication_failed")
                .doesNotContain("oidc failed");
        var query = SignInFailureRedirectTest.query(resp.getRedirectedUrl());
        assertThat(query.getFirst("message")).isEqualTo(SignInFailures.GENERIC_MESSAGE);
        assertThat(query.getFirst("reason")).isEqualTo("SSO_REJECTED");
        assertThat(query.getFirst("ref")).startsWith("req-http-");
        // session invalidated and SESSION cookie expired
        assertThat(session.isInvalid()).isTrue();
        Cookie sessionCookie = resp.getCookie("SESSION");
        assertThat(sessionCookie).isNotNull();
        assertThat(sessionCookie.getMaxAge()).isZero();
    }

    @Test
    void oidcFailure_noSession_stillRedirects() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/oauth2/code/reg");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        oidcHandler().onAuthenticationFailure(req, resp, new BadCredentialsException("x"));

        assertThat(resp.getRedirectedUrl()).startsWith(FRONTEND);
    }

    @Test
    void oidcFailure_emptyUri_usesUnknownRegistrationId() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        oidcHandler().onAuthenticationFailure(req, resp, new BadCredentialsException("x"));
        assertThat(resp.getRedirectedUrl()).startsWith(FRONTEND);
    }

    // ── The redirect carries the reason and the request id the audit row holds ──

    @Test
    void oidcFailure_refQuotesTheRequestIdTheAuditRowWasWrittenWith() throws Exception {
        AuthAuditRecorder audit = org.mockito.Mockito.mock(AuthAuditRecorder.class);
        String[] idDuringAudit = new String[1];
        org.mockito.Mockito.doAnswer(call -> {
            idDuringAudit[0] = com.certmanagement.interceptor.RequestContextInterceptor.getCurrentRequestId();
            return null;
        }).when(audit).ssoSignInFailed(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
        OidcAuthenticationFailureHandler handler = new OidcAuthenticationFailureHandler(audit,
                new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null));
        ReflectionTestUtils.setField(handler, "frontendRedirectUrl", FRONTEND);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        handler.onAuthenticationFailure(new MockHttpServletRequest("GET", "/login/oauth2/code/reg"), resp,
                new BadCredentialsException("x"));

        var query = SignInFailureRedirectTest.query(resp.getRedirectedUrl());
        assertThat(query.getFirst("reason")).isEqualTo("SSO_REJECTED");
        assertThat(idDuringAudit[0]).startsWith("req-http-");
        assertThat(query.getFirst("ref")).isEqualTo(idDuringAudit[0]);
        assertThat(com.certmanagement.interceptor.RequestContextInterceptor.getCurrentRequestId())
                .as("the callback puts back what the thread held").isEqualTo("unknown");
    }

    @Test
    void oidcFailure_refIsAlwaysMinted_anIncomingRequestIdIsOnlyTheCorrelationId() throws Exception {
        AuthAuditRecorder audit = org.mockito.Mockito.mock(AuthAuditRecorder.class);
        String[] idsDuringAudit = new String[2];
        org.mockito.Mockito.doAnswer(call -> {
            idsDuringAudit[0] = com.certmanagement.interceptor.RequestContextInterceptor.getCurrentRequestId();
            idsDuringAudit[1] = com.certmanagement.interceptor.RequestContextInterceptor.getCurrentCorrelationId();
            return null;
        }).when(audit).ssoSignInFailed(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
        OidcAuthenticationFailureHandler handler = new OidcAuthenticationFailureHandler(audit,
                new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null));
        ReflectionTestUtils.setField(handler, "frontendRedirectUrl", FRONTEND);
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/login/oauth2/code/reg");
        req.addHeader("X-Request-ID", "gw-1234");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        handler.onAuthenticationFailure(req, resp, new BadCredentialsException("x"));

        String ref = SignInFailureRedirectTest.query(resp.getRedirectedUrl()).getFirst("ref");
        assertThat(ref).as("never the id the client sent").startsWith("req-http-").isNotEqualTo("gw-1234");
        assertThat(idsDuringAudit[0]).isEqualTo(ref);
        assertThat(idsDuringAudit[1]).as("the incoming id is kept for tracing only").isEqualTo("gw-1234");
        assertThat(com.certmanagement.interceptor.RequestContextInterceptor.getCurrentCorrelationId())
                .as("the callback puts back what the thread held").isEqualTo("unknown");
    }

    @Test
    void oidcFailure_aRequestIdParameterIsAlsoOnlyTheCorrelationId_aHostileOneIsDropped() throws Exception {
        MockHttpServletRequest param = new MockHttpServletRequest("GET", "/login/oauth2/code/reg");
        param.setParameter("requestId", "chosen-by-link");
        MockHttpServletResponse paramResp = new MockHttpServletResponse();
        oidcHandler().onAuthenticationFailure(param, paramResp, new BadCredentialsException("x"));
        assertThat(SignInFailureRedirectTest.query(paramResp.getRedirectedUrl()).getFirst("ref"))
                .startsWith("req-http-").isNotEqualTo("chosen-by-link");

        MockHttpServletRequest hostile = new MockHttpServletRequest("GET", "/login/oauth2/code/reg");
        hostile.addHeader("X-Request-ID", "<img src=x onerror=alert(1)>");
        MockHttpServletResponse hostileResp = new MockHttpServletResponse();
        oidcHandler().onAuthenticationFailure(hostile, hostileResp, new BadCredentialsException("x"));
        assertThat(hostileResp.getRedirectedUrl()).doesNotContain("img").doesNotContain("onerror");
        assertThat(SignInFailureRedirectTest.query(hostileResp.getRedirectedUrl()).getFirst("ref"))
                .startsWith("req-http-");
    }

    @Test
    void theRegistrationIdInThePathIsNeitherStoredNorAnOrganization() throws Exception {
        AuthAuditRecorder audit = org.mockito.Mockito.mock(AuthAuditRecorder.class);
        OidcAuthenticationFailureHandler handler = new OidcAuthenticationFailureHandler(audit,
                new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null));
        ReflectionTestUtils.setField(handler, "frontendRedirectUrl", FRONTEND);

        handler.onAuthenticationFailure(new MockHttpServletRequest("GET", "/login/oauth2/code/org-9-made-up"),
                new MockHttpServletResponse(), new BadCredentialsException("x"));

        org.mockito.Mockito.verify(audit).ssoSignInFailed(null, null, AuthAuditRecorder.Method.OIDC, null,
                SignInFailures.SSO_REJECTED);
    }
}
