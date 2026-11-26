// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final ClientAddressResolver clientAddressResolver;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        String requestId = firstNonBlank(
            GatewayRequestContext.getRequestId(),
            request.getHeader("X-Request-ID"),
            "unknown"
        );
        String correlationId = firstNonBlank(
            GatewayRequestContext.getCorrelationId(),
            request.getHeader("X-Correlation-ID"),
            "unknown"
        );
        String requestPath = request.getRequestURI() +
            (StringUtils.hasText(request.getQueryString()) ? "?" + request.getQueryString() : "");
        boolean authHeaderPresent = StringUtils.hasText(request.getHeader("Authorization"));

        log.warn("[reqId={}|corrId={}] AUTH_EVENT resource-auth failure method={} path={} remoteIp={} authHeaderPresent={} reason={} cause={}",
            requestId,
            correlationId,
            request.getMethod(),
            requestPath,
            clientAddressResolver.resolve(request),
            authHeaderPresent,
            authHeaderPresent ? "invalid_token" : "missing_token",
            SignInFailures.causeOf(authException));

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("method", request.getMethod());
        body.put("path", requestPath);
        body.put("requestId", requestId);
        body.put("correlationId", correlationId);
        body.put("timestamp", Instant.now().toString());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private String firstNonBlank(String first, String second, String fallback) {
        if (StringUtils.hasText(first)) {
            return first;
        }
        if (StringUtils.hasText(second)) {
            return second;
        }
        return fallback;
    }
}
