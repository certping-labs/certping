// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class TrailingSlashNormalizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String requestUri = request.getRequestURI();
        if (requestUri.length() <= 1 || !requestUri.endsWith("/")) {
            filterChain.doFilter(request, response);
            return;
        }

        filterChain.doFilter(new NormalizedPathRequest(request, requestUri.substring(0, requestUri.length() - 1)), response);
    }

    private static final class NormalizedPathRequest extends HttpServletRequestWrapper {

        private final String requestUri;
        private final String servletPath;

        private NormalizedPathRequest(HttpServletRequest request, String requestUri) {
            super(request);
            this.requestUri = requestUri;
            String contextPath = request.getContextPath();
            this.servletPath = contextPath == null || contextPath.isBlank() || !requestUri.startsWith(contextPath)
                    ? requestUri
                    : requestUri.substring(contextPath.length());
        }

        @Override
        public String getRequestURI() {
            return requestUri;
        }

        @Override
        public StringBuffer getRequestURL() {
            String originalUrl = super.getRequestURL().toString();
            return new StringBuffer(originalUrl.substring(0, originalUrl.length() - 1));
        }

        @Override
        public String getServletPath() {
            return servletPath.isBlank() ? "/" : servletPath;
        }
    }
}
