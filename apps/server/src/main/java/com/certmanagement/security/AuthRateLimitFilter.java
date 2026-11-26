// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.Paths;
import com.certmanagement.service.FixedWindowRateLimiter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.OptionalLong;

/**
 * Per client address limits on the anonymous credential endpoints: sign-in (both paths), the second
 * factor, forgot-password, reset-password and the single sign-on code exchange. Each endpoint has its own
 * fixed-window counter per address ({@code certping.rate-limit.auth.*}); over it the answer is 429 with
 * {@code Retry-After}, before the request reaches the password check.
 *
 * <p>The address is {@link ClientAddressResolver}'s: by default ({@code certping.client-ip.source:
 * LAST_PROXY_HOP}) {@code X-Forwarded-For} is believed only when the connection comes from a private or
 * loopback address (Caddy or another proxy in front), and then only its rightmost entry, the one that proxy
 * appended. A client connecting directly cannot choose its counter by sending the header.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class AuthRateLimitFilter extends OncePerRequestFilter {

    static final String KEY_PREFIX = "auth-rate:";
    static final String SSO_EXCHANGE = "/api/auth/sso/exchange";
    private static final String RESET_PASSWORD_PREFIX = "/api/auth/reset-password/";

    /** Exact path to the counter's name. */
    private static final Map<String, String> ENDPOINTS = Map.of(
            Paths.AUTH_LOGIN, "login",
            Paths.ADMIN_LOGIN, "admin-login",
            Paths.AUTH_LOGIN_MFA, "login-mfa",
            Paths.AUTH_FORGOT_PASSWORD, "forgot-password",
            SSO_EXCHANGE, "sso-exchange");

    private final FixedWindowRateLimiter limiter;
    private final ClientAddressResolver clientAddressResolver;
    private final boolean enabled;
    private final int maxRequests;
    private final Duration window;

    public AuthRateLimitFilter(FixedWindowRateLimiter limiter, ClientAddressResolver clientAddressResolver,
                               @Value("${certping.rate-limit.auth.enabled:true}") boolean enabled,
                               @Value("${certping.rate-limit.auth.max-requests:20}") int maxRequests,
                               @Value("${certping.rate-limit.auth.window:PT5M}") Duration window) {
        if (maxRequests < 1) {
            throw new IllegalStateException("certping.rate-limit.auth.max-requests must be at least 1");
        }
        if (window.isNegative() || window.toSeconds() < 1) {
            throw new IllegalStateException("certping.rate-limit.auth.window must be at least one second");
        }
        this.limiter = limiter;
        this.clientAddressResolver = clientAddressResolver;
        this.enabled = enabled;
        this.maxRequests = maxRequests;
        this.window = window;
    }

    /** The counter a request to {@code path} counts on, or null when the path is not limited. */
    static String endpointOf(String path) {
        if (path == null) {
            return null;
        }
        String normalized = path.length() > 1 && path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        if (normalized.startsWith(RESET_PASSWORD_PREFIX)) {
            return "reset-password";
        }
        return ENDPOINTS.get(normalized);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !enabled || HttpMethod.OPTIONS.matches(request.getMethod()) || endpointOf(request.getRequestURI()) == null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String endpoint = endpointOf(request.getRequestURI());
        String client = clientAddressResolver.resolve(request);
        String key = KEY_PREFIX + endpoint + ":" + (client == null ? "unknown" : client);
        OptionalLong retryAfter = limiter.tryAcquire(key, maxRequests, window);
        if (retryAfter.isPresent()) {
            log.warn("AUTH_EVENT rate-limited endpoint={} client={} retryAfterSeconds={}",
                    endpoint, client, retryAfter.getAsLong());
            response.setStatus(429);
            response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfter.getAsLong()));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"status\":429,\"error\":\"Too Many Requests\",\"code\":\"RATE_LIMITED\","
                    + "\"message\":\"Too many attempts. Try again later.\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
