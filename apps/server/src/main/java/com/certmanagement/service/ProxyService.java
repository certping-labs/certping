// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.security.GatewayRequestContext;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

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
    private final ObjectMapper objectMapper;
    private final String notificationServiceBaseUrl;
    private final String internalToken;

    @org.springframework.beans.factory.annotation.Autowired
    public ProxyService(
            RestTemplate restTemplate,
            ObjectMapper objectMapper,
            @Value("${notification-service.base-url}") String notificationServiceBaseUrl,
            @Value("${certping.transport.internal-token:}") String internalToken) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.notificationServiceBaseUrl = notificationServiceBaseUrl;
        this.internalToken = internalToken == null ? "" : internalToken.trim();
    }

    /** A proxy that sends no internal token; the notifier refuses it, so only for tests. */
    public ProxyService(RestTemplate restTemplate, ObjectMapper objectMapper, String notificationServiceBaseUrl) {
        this(restTemplate, objectMapper, notificationServiceBaseUrl, "");
    }

    private String getNotificationServiceUrl() {
        return notificationServiceBaseUrl;
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
     * Enrich a JSON request body with userId, organizationId, and requestId from the gateway context.
     * Values from JWT always override any user-supplied values (prevents spoofing).
     */
    public String enrichJsonBody(String requestBody) {
        if (!GatewayRequestContext.isPresent()) {
            contextLogger().warn("GatewayRequestContext not set - forwarding body without enrichment");
            return requestBody;
        }

        try {
            Map<String, Object> bodyMap;
            if (requestBody != null && !requestBody.isBlank()) {
                bodyMap = objectMapper.readValue(requestBody, new TypeReference<Map<String, Object>>() {});
            } else {
                bodyMap = new LinkedHashMap<>();
            }

            Integer userId = GatewayRequestContext.getUserId();
            String organizationId = GatewayRequestContext.getOrganizationId();
            String requestId = GatewayRequestContext.getRequestId();
            String email = GatewayRequestContext.getEmail();
            String correlationId = GatewayRequestContext.getCorrelationId();

            // Inject flat top-level fields the notifier reads
            if (userId != null) {
                bodyMap.put("userId", userId);
            }
            if (organizationId != null) {
                bodyMap.put("organizationId", organizationId);
            }
            if (requestId != null) {
                bodyMap.put("requestId", requestId);
            }
            if (email != null) {
                bodyMap.put("email", email);
            }
            if (correlationId != null) {
                bodyMap.put("correlationId", correlationId);
            }

            // Inject/populate nested owner object (used by some downstream services)
            // Owner structure: { "userId": Integer, "organizationId": string }
            if (userId != null || organizationId != null) {
                @SuppressWarnings("unchecked")
                Map<String, Object> ownerMap = bodyMap.containsKey("owner") && bodyMap.get("owner") instanceof Map
                        ? (Map<String, Object>) bodyMap.get("owner")
                        : new LinkedHashMap<>();
                if (userId != null) {
                    ownerMap.put("userId", userId);
                }
                if (organizationId != null) {
                    ownerMap.put("organizationId", organizationId);
                }
                bodyMap.put("owner", ownerMap);
            }

            String enriched = objectMapper.writeValueAsString(bodyMap);
            contextLogger().debug("Enriched request body with userId={}, organizationId={}, requestId={}, owner populated={}",
                    userId, organizationId, requestId, bodyMap.containsKey("owner"));
            return enriched;

        } catch (Exception e) {
            contextLogger().warn("Failed to enrich JSON body, forwarding original. errorType={}",
                    e.getClass().getSimpleName());
            return requestBody;
        }
    }

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

    // ===== Explicit target routing (controller-driven) =====

    public ResponseEntity<String> post(String path, String requestBody) {
        String url = getNotificationServiceUrl() + path;
        String enrichedBody = enrichJsonBody(requestBody);
        contextLogger().info("Proxying POST request to path={}", path);

        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<String> entity = new HttpEntity<>(enrichedBody, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.POST, entity, String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying POST path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("POST", path, e);
        }
    }

    public ResponseEntity<String> put(String path, String requestBody) {
        String url = getNotificationServiceUrl() + path;
        String enrichedBody = enrichJsonBody(requestBody);
        contextLogger().info("Proxying PUT request to path={}", path);

        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<String> entity = new HttpEntity<>(enrichedBody, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.PUT, entity, String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying PUT path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("PUT", path, e);
        }
    }

    public ResponseEntity<String> get(String path, Map<String, String> queryParams) {
        Map<String, String> enrichedParams = enrichQueryParams(queryParams);
        StringBuilder url = new StringBuilder(getNotificationServiceUrl() + path);

        if (enrichedParams != null && !enrichedParams.isEmpty()) {
            url.append("?");
            enrichedParams.forEach((key, value) -> {
                if (value != null) {
                    url.append(key).append("=").append(value).append("&");
                }
            });
            // Remove trailing &
            url.setLength(url.length() - 1);
        }

        String finalUrl = url.toString();
        contextLogger().info("Proxying GET request to path={}", path);

        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    finalUrl, HttpMethod.GET, entity, String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying GET path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("GET", path, e);
        }
    }

    public ResponseEntity<String> delete(String path) {
        String url = getNotificationServiceUrl() + path;
        contextLogger().info("Proxying DELETE request to path={}", path);

        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.DELETE, entity, String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying DELETE path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("DELETE", path, e);
        }
    }

    public ResponseEntity<String> deleteWithBody(String path, String requestBody) {
        String url = getNotificationServiceUrl() + path;
        String enrichedBody = enrichJsonBody(requestBody);
        contextLogger().info("Proxying DELETE (with body) request to path={}", path);

        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<String> entity = new HttpEntity<>(enrichedBody, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.DELETE, entity, String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying DELETE path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("DELETE", path, e);
        }
    }

    public ResponseEntity<String> patch(String path, String requestBody) {
        String url = getNotificationServiceUrl() + path;
        String enrichedBody = enrichJsonBody(requestBody);
        contextLogger().info("Proxying PATCH request to path={}", path);

        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<String> entity = new HttpEntity<>(enrichedBody, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.PATCH, entity, String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying PATCH path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("PATCH", path, e);
        }
    }

    public ResponseEntity<String> patch(String path, String requestBody, Map<String, String> queryParams) {
        Map<String, String> enrichedParams = enrichQueryParams(queryParams);
        StringBuilder url = new StringBuilder(getNotificationServiceUrl() + path);

        if (enrichedParams != null && !enrichedParams.isEmpty()) {
            url.append("?");
            enrichedParams.forEach((key, value) -> {
                if (value != null) {
                    url.append(key).append("=").append(value).append("&");
                }
            });
            // Remove trailing &
            url.setLength(url.length() - 1);
        }

        String finalUrl = url.toString();
        String enrichedBody = enrichJsonBody(requestBody);
        contextLogger().info("Proxying PATCH request to path={}", path);

        try {
            HttpHeaders headers = createHeaders();
            HttpEntity<String> entity = new HttpEntity<>(enrichedBody, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    finalUrl, HttpMethod.PATCH, entity, String.class);
            return relay(response);

        } catch (HttpStatusCodeException e) {
            contextLogger().error("Error proxying PATCH path={} status={}", path, e.getStatusCode());
            return relayError(e);
        } catch (Exception e) {
            return relayUnexpected("PATCH", path, e);
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
