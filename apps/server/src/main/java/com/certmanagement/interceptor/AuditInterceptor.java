// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import com.certmanagement.audit.AuditContext;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditReasons;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditSubject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import com.certmanagement.constants.ActionType;
import com.certmanagement.constants.ResourceType;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Records every mutating API request (POST, PUT, PATCH, DELETE) as one internal {@code api.request} row in
 * {@code audit_events}: method, route pattern, status and duration; never the raw path, the query or the
 * caller's email. The row goes through the bounded async writer, so the request never waits on it.
 *
 * <p>Reads (GET, HEAD) and preflights (OPTIONS) are not persisted at all: a page load or a poll is not an
 * audit event. They are written to the application log as one line with the route pattern, the status and
 * the duration. The few reads of something sensitive are recorded explicitly, as access events
 * ({@link com.certmanagement.audit.AuditedRead}).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditInterceptor implements HandlerInterceptor {

    private final AuditRecorder recorder;

    // ThreadLocal to store pre-captured context (since GatewayRequestContext is cleared after filter chain)
    private static final ThreadLocal<RequestContext> AUDIT_CONTEXT = new ThreadLocal<>();

    /** When a read started (System.nanoTime), for its log line. */
    private static final String READ_STARTED = AuditInterceptor.class.getName() + ".READ_STARTED";

    // Paths to exclude from auditing (health checks, swagger, static resources, auth endpoints)
    private static final Set<String> EXCLUDED_PATH_PREFIXES = Set.of(
        "/actuator",
        "/swagger-ui",
        "/v3/api-docs",
        "/h2-console",
        "/error",
        // Agent and notifier message traffic: one request per message, authenticated by token.
        "/api/v1/agent-gateway"
    );

    /** Methods that change nothing: logged, never persisted. */
    private static final Set<String> READ_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try {
            String path = request.getRequestURI();
            String method = request.getMethod();

            // Skip excluded paths
            if (shouldExclude(path)) {
                return true;
            }
            if (isRead(method)) {
                request.setAttribute(READ_STARTED, System.nanoTime());
                return true;
            }

            // Capture the actor and origin now, while GatewayRequestContext is still populated.
            AUDIT_CONTEXT.set(new RequestContext(method, path, System.nanoTime(), AuditContext.actor(),
                    AuditContext.origin()));
        } catch (Exception e) {
            log.warn("Failed to capture audit context in preHandle: {}", e.getMessage());
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, 
                                 Object handler, Exception ex) {
        try {
            RequestContext ctx = AUDIT_CONTEXT.get();
            if (ctx == null) {
                logRead(request, response);
                return; // A read, an excluded path, or preHandle failed
            }

            int statusCode = response.getStatus();
            Object pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
            String route = pattern instanceof String matched ? matched : null;
            long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.startNanos());
            log.info("request finished method={} route={} status={} durationMs={}", ctx.method(),
                    route == null ? "-" : route, statusCode, durationMs);

            Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("method", ctx.method().toUpperCase(Locale.ROOT));
            if (route != null) {
                attributes.put("route", route);
            }
            attributes.put("status", Integer.toString(statusCode));
            attributes.put("durationMs", Long.toString(durationMs));
            AuditEventRow row = AuditEvents.internalAs(AuditEventType.API_REQUEST,
                    AuditSubject.builder().attributes(attributes).build(), AuditReasons.ofStatus(statusCode),
                    ctx.actor(), ctx.origin());
            // The method's action and the path's resource, so the platform view filters requests by them.
            recorder.recordAsync(row.toBuilder()
                    .action(mapHttpMethodToAction(ctx.method()))
                    .resourceType(categorizeResource(ctx.path()))
                    .build());

        } catch (Exception e) {
            log.warn("Failed to create audit log in afterCompletion: {}", e.getMessage());
        } finally {
            AUDIT_CONTEXT.remove();
        }
    }

    /** Health checks, API docs and the error page are never recorded. */
    private boolean shouldExclude(String path) {
        for (String prefix : EXCLUDED_PATH_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isRead(String method) {
        return method == null || READ_METHODS.contains(method.toUpperCase(Locale.ROOT));
    }

    /**
     * One application log line for a read: the route pattern, never the raw path or query, so no identifier
     * or search term a caller typed is logged. OPTIONS preflights are left out.
     */
    private static void logRead(HttpServletRequest request, HttpServletResponse response) {
        if (!(request.getAttribute(READ_STARTED) instanceof Long started)
                || "OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return;
        }
        Object pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        log.info("request finished method={} route={} status={} durationMs={}", request.getMethod(),
                pattern instanceof String route ? route : "-", response.getStatus(),
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
    }

    /**
     * Map HTTP method to an audit action string.
     */
    private String mapHttpMethodToAction(String httpMethod) {
        return switch (httpMethod.toUpperCase(Locale.ROOT)) {
            case "POST" -> ActionType.API_CREATE.name();
            case "PUT" -> ActionType.API_UPDATE.name();
            case "PATCH" -> ActionType.API_PATCH.name();
            case "DELETE" -> ActionType.API_DELETE.name();
            default -> "API_" + httpMethod.toUpperCase(Locale.ROOT);
        };
    }


    /** Categorize the API path into a resource type for audit grouping. */
    private String categorizeResource(String path) {
        return ResourceType.fromPath(path).name();
    }

    /** What preHandle captured for the request's row. */
    private record RequestContext(String method, String path, long startNanos, AuditContext.Actor actor,
                                  AuditContext.Origin origin) {
    }
}
