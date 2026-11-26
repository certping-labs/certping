// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter that caches JSON request bodies so they can be read multiple times —
 * first by {@link RequestContextInterceptor} to extract correlationId (and other
 * context fields), then by Spring's @RequestBody processing.
 *
 * <p>The cached body bytes are stored as a <b>request attribute</b>
 * ({@value #CACHED_BODY_ATTR}) so they survive any subsequent request wrapping
 * by Spring Security's {@code FirewalledRequest} or other wrappers.</p>
 *
 * <p>Only caches for Content-Type containing "application/json" on /api/** paths.
 * Non-JSON requests (GET with no body, multipart uploads, etc.) pass through untouched.</p>
 */
@Component
// After AgentGatewayBodyLimitFilter (HIGHEST_PRECEDENCE), which caps the bodies this buffers, and after
// AuthRateLimitFilter, so a refused sign-in is never buffered.
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RequestBodyCachingFilter extends OncePerRequestFilter {

    /** Request attribute key where the cached body bytes are stored. */
    public static final String CACHED_BODY_ATTR = "com.certmanagement.CACHED_REQUEST_BODY";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String contentType = request.getContentType();
        if (contentType != null && contentType.contains("application/json")) {
            CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
            // Store as attribute so downstream interceptors can read body even after
            // Spring Security wraps the request in FirewalledRequest.
            cachedRequest.setAttribute(CACHED_BODY_ATTR, cachedRequest.getCachedBody());
            filterChain.doFilter(cachedRequest, response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only cache body for /api/** paths — skip actuator, static resources, etc.
        return !request.getRequestURI().startsWith("/api/");
    }
}
