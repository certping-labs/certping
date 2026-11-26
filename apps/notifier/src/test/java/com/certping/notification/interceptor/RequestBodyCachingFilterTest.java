// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.interceptor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.BufferedReader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RequestBodyCachingFilterTest {

    private RequestBodyCachingFilter filter;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        filter = new RequestBodyCachingFilter();
        response = new MockHttpServletResponse();
    }

    @Test
    void doFilterInternal_jsonContentType_wrapsRequestAndCachesBody() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/notifications");
        req.setContentType("application/json");
        req.setContent("{\"foo\":\"bar\"}".getBytes());
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, response, chain);

        ArgumentCaptor<ServletRequest> captor = ArgumentCaptor.forClass(ServletRequest.class);
        verify(chain).doFilter(captor.capture(), org.mockito.ArgumentMatchers.any());
        HttpServletRequest wrapped = (HttpServletRequest) captor.getValue();
        assertThat(wrapped).isInstanceOf(CachedBodyHttpServletRequest.class);
        // The cached body attribute is now populated on the wrapped request.
        byte[] cached = (byte[]) wrapped.getAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR);
        assertThat(new String(cached)).isEqualTo("{\"foo\":\"bar\"}");
    }

    @Test
    void doFilterInternal_jsonContentTypeWithCharset_stillWraps() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/x");
        req.setContentType("application/json; charset=utf-8");
        req.setContent("{}".getBytes());
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, response, chain);

        ArgumentCaptor<ServletRequest> captor = ArgumentCaptor.forClass(ServletRequest.class);
        verify(chain).doFilter(captor.capture(), org.mockito.ArgumentMatchers.any());
        assertThat(captor.getValue()).isInstanceOf(CachedBodyHttpServletRequest.class);
    }

    @Test
    void doFilterInternal_nonJson_passesRequestThrough() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/upload");
        req.setContentType("multipart/form-data");
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, response, chain);

        // Not wrapped — the exact request is passed through
        verify(chain).doFilter(req, response);
    }

    @Test
    void doFilterInternal_nullContentType_passesThrough() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/notifications");
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, response, chain);

        verify(chain).doFilter(req, response);
    }

    @Test
    void shouldNotFilter_nonApiPath_returnsTrue() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/actuator/health");

        // shouldNotFilter is protected — the OncePerRequestFilter contract short-circuits it
        // by NOT calling doFilterInternal. Easiest to just check by calling doFilter twice
        // and ensuring the same request instance is passed through even on JSON content.
        req.setContentType("application/json");
        req.setContent("{\"x\":1}".getBytes());
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, response, chain);

        // shouldNotFilter=true → doFilterInternal not invoked → request passed as-is
        verify(chain).doFilter(req, response);
    }

    @Test
    void cachedBodyHttpServletRequest_getInputStreamRereadable() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/x");
        req.setContentType("application/json");
        req.setContent("{\"a\":1}".getBytes());

        CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(req);

        // Reading the stream twice must both succeed with identical bytes — that's the
        // whole point of caching.
        String first = new String(wrapped.getInputStream().readAllBytes());
        String second = new String(wrapped.getInputStream().readAllBytes());
        assertThat(first).isEqualTo("{\"a\":1}");
        assertThat(second).isEqualTo("{\"a\":1}");
    }

    @Test
    void cachedBodyHttpServletRequest_getReaderRereadable() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/x");
        req.setContentType("application/json");
        req.setContent("{\"z\":\"9\"}".getBytes());

        CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(req);

        try (BufferedReader r = wrapped.getReader()) {
            assertThat(r.readLine()).isEqualTo("{\"z\":\"9\"}");
        }
        // Second read still works from the cached bytes.
        try (BufferedReader r2 = wrapped.getReader()) {
            assertThat(r2.readLine()).isEqualTo("{\"z\":\"9\"}");
        }
    }

    @Test
    void cachedBodyHttpServletRequest_getCachedBody_returnsBytes() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/x");
        req.setContentType("application/json");
        req.setContent("body-bytes".getBytes());

        CachedBodyHttpServletRequest wrapped = new CachedBodyHttpServletRequest(req);

        assertThat(new String(wrapped.getCachedBody())).isEqualTo("body-bytes");
    }
}
