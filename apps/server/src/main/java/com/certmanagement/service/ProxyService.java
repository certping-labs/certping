// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.security.GatewayRequestContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

import java.util.LinkedHashMap;
import java.util.Map;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

/**
 * Proxy service for forwarding requests to the notifier ({@code apps/notifier}).
 */
@Service
@Slf4j
public class ProxyService {

    private final RestTemplate restTemplate;
    private final String notificationServiceBaseUrl;
    private final String internalToken;

    @org.springframework.beans.factory.annotation.Autowired
    public ProxyService(
            RestTemplate restTemplate,
            @Value("${notification-service.base-url}") String notificationServiceBaseUrl,
            @Value("${certping.transport.internal-token:}") String internalToken) {
        this.restTemplate = restTemplate;
        this.notificationServiceBaseUrl = notificationServiceBaseUrl;
        this.internalToken = internalToken == null ? "" : internalToken.trim();
    }

    /** A proxy that sends no internal token; the notifier refuses it, so only for tests. */
    public ProxyService(RestTemplate restTemplate, String notificationServiceBaseUrl) {
        this(restTemplate, notificationServiceBaseUrl, "");
    }

    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));
        // The notifier answers only the internal token (its InternalTokenFilter).
        if (!internalToken.isEmpty()) {
            headers.setBearerAuth(internalToken);
        }

        // Forward requestId & correlationId as HTTP headers so downstream interceptors can extract them
        if (GatewayRequestContext.isPresent()) {
            String requestId = GatewayRequestContext.getRequestId();
            String correlationId = GatewayRequestContext.getCorrelationId();
            if (requestId != null) {
                headers.set("X-Request-ID", requestId);
            }
            if (correlationId != null) {
                headers.set("X-Correlation-ID", correlationId);
            }
        }
        return headers;
    }

    /**
     * Relay a downstream response: just forward status code + JSON body directly.
     * No downstream headers are forwarded — they're internal services.
     */
    private ResponseEntity<String> relay(ResponseEntity<String> response) {
        return ResponseEntity.status(response.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(response.getBody());
    }

    /**
     * Relay a downstream error response: status code + error body.
     */
    private ResponseEntity<String> relayError(HttpStatusCodeException e) {
        return ResponseEntity.status(e.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(e.getResponseBodyAsString());
    }

    /**
     * Map a non-HTTP proxy failure to a response. A {@link ResourceAccessException}
     * (connect/read timeout, connection refused) is the downstream being slow or
     * unreachable — a 504, not a 500 — so callers and dashboards can tell "notifier
     * timed out" apart from a genuine gateway bug.
     */
    private ResponseEntity<String> relayUnexpected(String verb, String path, Exception e) {
        if (e instanceof ResourceAccessException) {
            contextLogger().error("Timeout proxying {} path={} errorType={}",
                    verb, path, e.getClass().getSimpleName());
            return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"success\":false,\"message\":\"Notification service timed out\"}");
        }
        contextLogger().error("Unexpected error proxying {} path={} errorType={}",
                verb, path, e.getClass().getSimpleName());
        return ResponseEntity.internalServerError()
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"success\":false,\"message\":\"Proxy error\"}");
    }

    // ===== Gateway Context Enrichment =====

    /**
     * Enrich query parameters with userId, organizationId, and requestId from the gateway context.
     * Values from JWT always override any user-supplied values (prevents spoofing).
     */
    public Map<String, String> enrichQueryParams(Map<String, String> queryParams) {
        if (!GatewayRequestContext.isPresent()) {
            contextLogger().warn("GatewayRequestContext not set - forwarding params without enrichment");
            return queryParams;
        }

        Map<String, String> enriched = queryParams != null ? new LinkedHashMap<>(queryParams) : new LinkedHashMap<>();

        Integer userId = GatewayRequestContext.getUserId();
        String organizationId = GatewayRequestContext.getOrganizationId();
        String requestId = GatewayRequestContext.getRequestId();
        String email = GatewayRequestContext.getEmail();
        String correlationId = GatewayRequestContext.getCorrelationId();

        if (userId != null) {
            enriched.put("userId", String.valueOf(userId));
        }
        if (organizationId != null) {
            enriched.put("organizationId", organizationId);
        }
        if (requestId != null) {
            enriched.put("requestId", requestId);
        }
        if (email != null) {
            enriched.put("email", email);
        }
        if (correlationId != null) {
            enriched.put("correlationId", correlationId);
        }

        contextLogger().debug("Enriched query params with userId={}, organizationId={}, requestId={}, correlationId={}",
                userId, organizationId, requestId, correlationId);
        return enriched;
    }

    public ResponseEntity<String> get(String path, Map<String, String> queryParams) {
        UriComponentsBuilder uri = UriComponentsBuilder.fromUriString(notificationServiceBaseUrl).path(path);
        Map<String, String> enrichedParams = enrichQueryParams(queryParams);
        if (enrichedParams != null) {
            enrichedParams.forEach((key, value) -> {
                if (value != null) {
                    uri.queryParam(key, value);
                }
            });
        }
        // Encoded as values, so a parameter can never add another one (such as organizationId).
        URI target = uri.encode().build().toUri();
        contextLogger().info("Proxying GET request to path={}", path);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    target, HttpMethod.GET, new HttpEntity<Void>(createHeaders()), String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying GET path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("GET", path, e);
        }
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(ProxyService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
