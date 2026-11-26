// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.service.FixedWindowRateLimiter;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.OptionalLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthRateLimitFilterTest {

    private final FixedWindowRateLimiter limiter = mock(FixedWindowRateLimiter.class);
    private final AuthRateLimitFilter filter = new AuthRateLimitFilter(limiter,
            new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null), true, 20, Duration.ofMinutes(5));

    @Test
    void everyCredentialEndpointIsLimitedOnItsOwnCounter() {
        assertThat(AuthRateLimitFilter.endpointOf("/api/auth/login")).isEqualTo("login");
        assertThat(AuthRateLimitFilter.endpointOf("/api/v1/admin/login")).isEqualTo("admin-login");
        assertThat(AuthRateLimitFilter.endpointOf("/api/auth/login/mfa")).isEqualTo("login-mfa");
        assertThat(AuthRateLimitFilter.endpointOf("/api/auth/forgot-password/")).isEqualTo("forgot-password");
        assertThat(AuthRateLimitFilter.endpointOf("/api/auth/reset-password/abc.def")).isEqualTo("reset-password");
        assertThat(AuthRateLimitFilter.endpointOf("/api/auth/sso/exchange")).isEqualTo("sso-exchange");
        assertThat(AuthRateLimitFilter.endpointOf("/api/auth/me")).isNull();
        assertThat(AuthRateLimitFilter.endpointOf("/api/v1/certs")).isNull();
    }

    @Test
    void overTheLimitIsA429WithRetryAfterAndNeverReachesTheSignIn() throws Exception {
        when(limiter.tryAcquire(anyString(), eq(20), eq(Duration.ofMinutes(5)))).thenReturn(OptionalLong.of(42));
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setRemoteAddr("203.0.113.9");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(429);
        assertThat(resp.getHeader("Retry-After")).isEqualTo("42");
        assertThat(resp.getContentAsString()).contains("RATE_LIMITED");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void underTheLimitTheRequestGoesOn() throws Exception {
        when(limiter.tryAcquire(anyString(), anyInt(), any())).thenReturn(OptionalLong.empty());
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/forgot-password");
        req.setRemoteAddr("203.0.113.9");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        verify(chain).doFilter(req, resp);
        verify(limiter).tryAcquire(eq("auth-rate:forgot-password:203.0.113.9"), eq(20), eq(Duration.ofMinutes(5)));
    }

    @Test
    void aDirectClientCannotPickItsCounterWithXForwardedFor() throws Exception {
        when(limiter.tryAcquire(anyString(), anyInt(), any())).thenReturn(OptionalLong.empty());
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setRemoteAddr("203.0.113.9");
        req.addHeader("X-Forwarded-For", "198.51.100.1");

        filter.doFilter(req, new MockHttpServletResponse(), mock(FilterChain.class));

        verify(limiter).tryAcquire(eq("auth-rate:login:203.0.113.9"), anyInt(), any());
    }

    @Test
    void behindALocalProxyTheProxysEntryIsTheClient() throws Exception {
        when(limiter.tryAcquire(anyString(), anyInt(), any())).thenReturn(OptionalLong.empty());
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        req.setRemoteAddr("127.0.0.1");
        req.addHeader("X-Forwarded-For", "6.6.6.6, 198.51.100.1");

        filter.doFilter(req, new MockHttpServletResponse(), mock(FilterChain.class));

        verify(limiter).tryAcquire(eq("auth-rate:login:198.51.100.1"), anyInt(), any());
    }

    @Test
    void otherPathsAreNotCounted() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(new MockHttpServletRequest("GET", "/api/v1/certs"), new MockHttpServletResponse(), chain);
        verifyNoInteractions(limiter);
    }
}
