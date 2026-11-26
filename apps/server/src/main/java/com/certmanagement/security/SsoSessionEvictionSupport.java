// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;

/**
 * Shared SSO callback cleanup helper.
 *
 * Explicitly invalidates any active server session and expires the Spring
 * Session cookie so callback state cannot be reused.
 */
final class SsoSessionEvictionSupport {

    private static final String SPRING_SESSION_COOKIE = "SESSION";

    private SsoSessionEvictionSupport() {
    }

    static void evictSessionAndCookies(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Logger log,
                                       String flow) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            try {
                session.invalidate();
                log.debug("[{}] Invalidated callback session", flow);
            } catch (IllegalStateException ignored) {
                log.debug("[{}] Session already invalidated", flow);
            }
        } else {
            log.debug("[{}] No active callback session found", flow);
        }

        expireCookie(request, response, SPRING_SESSION_COOKIE);
    }

    private static void expireCookie(HttpServletRequest request,
                                     HttpServletResponse response,
                                     String name) {
        Cookie cookie = new Cookie(name, "");
        String contextPath = request.getContextPath();
        cookie.setPath((contextPath == null || contextPath.isBlank()) ? "/" : contextPath);
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
