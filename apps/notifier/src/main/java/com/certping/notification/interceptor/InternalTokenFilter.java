// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.interceptor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Every HTTP endpoint of the notifier answers only a caller holding the internal token
 * ({@code CERTPING_INTERNAL_TOKEN}), sent as {@code Authorization: Bearer <token>} and compared in
 * constant time. The one exception is {@code /actuator/health} and its groups, which say UP or DOWN
 * and nothing else, so container and Kubernetes probes work without a secret.
 *
 * <p>With no token configured nothing but health is answered: the notifier cannot reach the server
 * without one either, so a missing token is a broken install, not an open one.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class InternalTokenFilter extends OncePerRequestFilter {

    static final String HEALTH = "/actuator/health";

    private final byte[] token;

    public InternalTokenFilter(@Value("${notifier.transport.token:}") String token) {
        String trimmed = token == null ? "" : token.trim();
        this.token = trimmed.getBytes(StandardCharsets.UTF_8);
        if (trimmed.isEmpty()) {
            log.warn("CERTPING_INTERNAL_TOKEN is not set: every notifier endpoint but health refuses requests");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && path.startsWith(context)) {
            path = path.substring(context.length());
        }
        return path.equals(HEALTH) || path.startsWith(HEALTH + "/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!authorized(request.getHeader("Authorization"))) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"success\":false,\"message\":\"internal token required\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    boolean authorized(String authorization) {
        if (token.length == 0 || authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        byte[] supplied = authorization.substring(7).trim().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(token, supplied);
    }
}
