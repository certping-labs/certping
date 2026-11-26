// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Seeds the SLF4J MDC for every inbound HTTP request the agent receives.
 *
 * <p>The agent today is primarily a gateway consumer, but it also exposes Spring Boot actuator
 * endpoints (and may grow REST endpoints later). Without this filter, every HTTP log line — the
 * actuator's request log, any future controller log, errors thrown from a Spring MVC handler —
 * would have an empty {@code [req= corr= msg=]} prefix.
 *
 * <p>Behavior:
 * <ul>
 *   <li>{@code requestId}: from {@code X-Request-ID} header, or generated as {@code req-http-<uuid>}.</li>
 *   <li>{@code correlationId}: from {@code X-Correlation-ID} header (left empty if absent — we don't
 *       fabricate a correlation ID because that's a cross-system identifier owned by the caller).</li>
 *   <li>{@code messageId}: from {@code X-Message-ID} header (used by callers that originated from a
 *       gateway message and want to maintain the chain).</li>
 * </ul>
 *
 * <p>Cleared in a finally to avoid bleeding into the next request handled on the same pooled
 * Servlet thread.
 */
@Component
public class TraceMdcFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestId = headerOrDefault(request, "X-Request-ID", "req-http-" + shortUuid());
        String correlationId = request.getHeader("X-Correlation-ID");
        String messageId = request.getHeader("X-Message-ID");
        try {
            MDC.put("requestId", requestId);
            if (correlationId != null && !correlationId.isEmpty()) {
                MDC.put("correlationId", correlationId);
            }
            if (messageId != null && !messageId.isEmpty()) {
                MDC.put("messageId", messageId);
            }
            // Echo the resolved requestId on the response so the caller can correlate too. We
            // never echo correlationId/messageId because those are caller-owned identifiers; we
            // simply propagate them inbound and forward downstream — not back upstream.
            response.setHeader("X-Request-ID", requestId);
            chain.doFilter(request, response);
        } finally {
            MDC.remove("requestId");
            MDC.remove("correlationId");
            MDC.remove("messageId");
        }
    }

    private static String headerOrDefault(HttpServletRequest request, String header, String fallback) {
        String value = request.getHeader(header);
        return (value == null || value.isEmpty()) ? fallback : value;
    }

    private static String shortUuid() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
