// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.interceptor;

import com.certping.notification.util.OtelSpanContext;
import com.certping.notification.utils.MessageIds;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Interceptor to extract and store request context (requestId, correlationId, idempotencyKey)
 * from request headers, query parameters, or JSON request body for use in exception handling and logging.
 */
@Component
public class RequestContextInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(RequestContextInterceptor.class);
    private static final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private static final String UNKNOWN = "unknown";

    public static final String MDC_REQUEST_ID = "requestId";
    public static final String MDC_CORRELATION_ID = "correlationId";
    public static final String MDC_NOTIFICATION_KEY = "notificationKey";

    private static final ThreadLocal<String> REQUEST_ID_HOLDER = new ThreadLocal<>();
    private static final ThreadLocal<String> CORRELATION_ID_HOLDER = new ThreadLocal<>();
    private static final ThreadLocal<String> IDEMPOTENCY_KEY_HOLDER = new ThreadLocal<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestId = extractValue(request, "X-Request-ID", "requestId");
        String correlationId = extractValue(request, "X-Correlation-ID", "correlationId");
        String idempotencyKey = request.getHeader("X-Idempotency-Key");

        // Fallback: extract from cached JSON body if not found in headers/query params
        if (correlationId == null) {
            correlationId = extractFieldFromBody(request, "correlationId");
        }
        if (requestId == null) {
            requestId = extractFieldFromBody(request, "requestId");
        }

        REQUEST_ID_HOLDER.set(requestId != null ? requestId : "unknown");
        CORRELATION_ID_HOLDER.set(correlationId != null ? correlationId : "unknown");
        if (idempotencyKey != null && !idempotencyKey.isEmpty()) {
            IDEMPOTENCY_KEY_HOLDER.set(idempotencyKey);
        }

        OtelSpanContext.enrichHttp(
                requestId != null ? requestId : null,
                correlationId != null ? correlationId : null);

        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        clearContext();
    }

    private String extractValue(HttpServletRequest request, String headerName, String paramName) {
        String value = request.getHeader(headerName);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        value = request.getParameter(paramName);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return null;
    }

    /**
     * Extract a field value from the cached JSON request body.
     * The body is stored as a request attribute by {@link RequestBodyCachingFilter}
     * so it survives Spring Security's FirewalledRequest wrapping.
     */
    private String extractFieldFromBody(HttpServletRequest request, String fieldName) {
        try {
            Object attr = request.getAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR);
            if (!(attr instanceof byte[] body) || body.length == 0) {
                return null;
            }
            JsonNode root = objectMapper.readTree(body);
            JsonNode node = root.get(fieldName);
            if (node != null && !node.isNull() && node.isString()) {
                String value = node.asString();
                return value.isEmpty() ? null : value;
            }
        } catch (Exception e) {
            log.debug("Could not extract {} from request body: {}", fieldName, e.getMessage());
        }
        return null;
    }

    public static String getCurrentRequestId() {
        String requestId = REQUEST_ID_HOLDER.get();
        return requestId != null ? requestId : "unknown";
    }

    public static String getCurrentCorrelationId() {
        String correlationId = CORRELATION_ID_HOLDER.get();
        return correlationId != null ? correlationId : "unknown";
    }

    public static String getCurrentIdempotencyKey() {
        String idempotencyKey = IDEMPOTENCY_KEY_HOLDER.get();
        return idempotencyKey != null ? idempotencyKey : "none";
    }

    public static void setCurrentRequestId(String requestId) {
        set(REQUEST_ID_HOLDER, MDC_REQUEST_ID, requestId);
    }

    public static void setCurrentCorrelationId(String correlationId) {
        set(CORRELATION_ID_HOLDER, MDC_CORRELATION_ID, correlationId);
    }

    public static void setCurrentIdempotencyKey(String idempotencyKey) {
        IDEMPOTENCY_KEY_HOLDER.set(idempotencyKey);
    }

    /**
     * The idempotency key of the notification being delivered, in its loggable form: every line
     * the thread logs carries it.
     */
    public static void setCurrentNotificationKey(String notificationKey) {
        set(IDEMPOTENCY_KEY_HOLDER, MDC_NOTIFICATION_KEY, MessageIds.loggable(notificationKey));
    }

    public static void clearContext() {
        REQUEST_ID_HOLDER.remove();
        CORRELATION_ID_HOLDER.remove();
        IDEMPOTENCY_KEY_HOLDER.remove();
        MDC.remove(MDC_REQUEST_ID);
        MDC.remove(MDC_CORRELATION_ID);
        MDC.remove(MDC_NOTIFICATION_KEY);
    }

    /**
     * The id is also put in MDC, so every line the thread logs carries it: only a valid one, and
     * never the placeholder of an id nobody sent.
     */
    private static void set(ThreadLocal<String> holder, String mdcKey, String id) {
        holder.set(id);
        String valid = MessageIds.valid(id);
        if (valid == null || UNKNOWN.equals(valid)) {
            MDC.remove(mdcKey);
        } else {
            MDC.put(mdcKey, valid);
        }
    }

    public static String getFormattedContext() {
        String requestId = getCurrentRequestId();
        String correlationId = getCurrentCorrelationId();
        String idempotencyKey = getCurrentIdempotencyKey();

        StringBuilder context = new StringBuilder();
        context.append("requestId=").append(requestId);
        context.append(", correlationId=").append(correlationId);
        if (!"none".equals(idempotencyKey)) {
            context.append(", idempotencyKey=").append(idempotencyKey);
        }
        return context.toString();
    }
}
