// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/** Unit tests for {@link RequestBodyCachingFilter}. */
@ExtendWith(MockitoExtension.class)
class RequestBodyCachingFilterTest {

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain chain;

    private final RequestBodyCachingFilter filter = new RequestBodyCachingFilter();

    private ServletInputStream stream(String body) {
        ByteArrayInputStream backing = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        return new ServletInputStream() {
            @Override public boolean isFinished() { return backing.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener l) { }
            @Override public int read() { return backing.read(); }
        };
    }

    @Test
    void wrapsJsonRequestAndStoresCachedBodyAttribute() throws Exception {
        when(request.getContentType()).thenReturn("application/json");
        when(request.getInputStream()).thenReturn(stream("{\"a\":1}"));

        filter.doFilterInternal(request, response, chain);

        ArgumentCaptor<HttpServletRequest> wrapped = ArgumentCaptor.forClass(HttpServletRequest.class);
        verify(chain).doFilter(wrapped.capture(), eq(response));
        assertThat(wrapped.getValue()).isInstanceOf(CachedBodyHttpServletRequest.class);
        // The filter stores the cached body as an attribute; verify it set it on the wrapper
        // (delegated to the underlying mock) and that the cached bytes round-trip.
        byte[] cached = ((CachedBodyHttpServletRequest) wrapped.getValue()).getCachedBody();
        assertThat(new String(cached, StandardCharsets.UTF_8)).isEqualTo("{\"a\":1}");
        verify(request).setAttribute(eq(RequestBodyCachingFilter.CACHED_BODY_ATTR), any());
    }

    @Test
    void passesThroughNonJsonRequestUnwrapped() throws Exception {
        when(request.getContentType()).thenReturn("text/plain");

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(request, never()).getInputStream();
    }

    @Test
    void passesThroughWhenContentTypeNull() throws Exception {
        when(request.getContentType()).thenReturn(null);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void shouldNotFilterForNonApiPaths() {
        when(request.getRequestURI()).thenReturn("/actuator/health");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void filtersApiPaths() {
        when(request.getRequestURI()).thenReturn("/api/v1/certs");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }
}
