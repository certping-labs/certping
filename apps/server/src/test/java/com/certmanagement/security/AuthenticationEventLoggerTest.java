// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class AuthenticationEventLoggerTest {

    private final AuthenticationEventLogger logger =
            new AuthenticationEventLogger(new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null));

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void logsTheResolvedClientOfTheCurrentRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.1");
        req.addHeader("X-Forwarded-For", "198.51.100.66, 203.0.113.9");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req));
        TestingAuthenticationToken auth = new TestingAuthenticationToken("user@x.com", null);
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

        assertThat(logger.resolveDetails(auth)).startsWith("remoteIp=203.0.113.9,");
    }

    @Test
    void outsideARequestLogsTheAddressSpringSecurityCaptured() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.1");
        TestingAuthenticationToken auth = new TestingAuthenticationToken("user@x.com", null);
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

        assertThat(logger.resolveDetails(auth)).startsWith("remoteIp=10.0.0.1,");
    }

    @Test
    void onAuthenticationSuccess_withWebDetails_logsWithoutError() {
        Authentication auth = new TestingAuthenticationToken("user@x.com", null,
                AuthorityUtils.createAuthorityList("ROLE_VIEWER"));
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.1");
        ((TestingAuthenticationToken) auth).setDetails(
                new WebAuthenticationDetailsSource().buildDetails(req));

        assertThatCode(() -> logger.onAuthenticationSuccess(new AuthenticationSuccessEvent(auth)))
                .doesNotThrowAnyException();
    }

    @Test
    void onAuthenticationSuccess_withoutDetails_logsNone() {
        Authentication auth = new TestingAuthenticationToken("user@x.com", null);
        assertThatCode(() -> logger.onAuthenticationSuccess(new AuthenticationSuccessEvent(auth)))
                .doesNotThrowAnyException();
    }

    @Test
    void onAuthenticationFailure_withException_logsWithoutError() {
        Authentication auth = new TestingAuthenticationToken("user@x.com", "creds");
        AuthenticationFailureBadCredentialsEvent event =
                new AuthenticationFailureBadCredentialsEvent(auth, new BadCredentialsException("bad"));

        assertThatCode(() -> logger.onAuthenticationFailure(event)).doesNotThrowAnyException();
    }
}
