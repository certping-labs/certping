// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

/**
 * ThreadLocal-based holder for gateway request context.
 * Populated by JwtAuthenticationFilter after JWT validation.
 * Used by ProxyService and controllers to enrich outgoing requests
 * with userId, organizationId, and requestId before forwarding to downstream services.
 *
 * <p>The frontend does NOT send userId/organizationId/requestId — these are
 * extracted from the JWT (userId, organizationId) and generated (requestId)
 * at the gateway level before proxying downstream.</p>
 */
public final class GatewayRequestContext {

    private static final ThreadLocal<RequestContext> CONTEXT = new ThreadLocal<>();

    private GatewayRequestContext() {
        // utility class
    }

    /**
     * Set the request context for the current thread.
     */
    public static void set(Integer userId, String organizationId, String requestId, String email) {
        CONTEXT.set(new RequestContext(userId, organizationId, requestId, email));
    }

    /**
     * Get the current request context.
     * @return the context, or null if not set
     */
    public static RequestContext get() {
        return CONTEXT.get();
    }

    /**
     * Get userId from current context.
     * @return userId or null
     */
    public static Integer getUserId() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.userId() : null;
    }

    /**
     * Get organizationId from current context.
     * @return organizationId or null
     */
    public static String getOrganizationId() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.organizationId() : null;
    }

    /**
     * Get requestId from current context.
     * @return requestId or null
     */
    public static String getRequestId() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.requestId() : null;
    }

    /**
     * Get email from current context.
     * @return email or null
     */
    public static String getEmail() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.email() : null;
    }

    /**
     * Clear the context (must be called after request completes to prevent memory leaks).
     */
    public static void clear() {
        CONTEXT.remove();
    }

    /**
     * Check if context is populated.
     */
    public static boolean isPresent() {
        return CONTEXT.get() != null;
    }

    /**
     * Set correlationId on the current context (called by RequestContextInterceptor after extracting from client headers).
     */
    public static void setCorrelationId(String correlationId) {
        RequestContext ctx = CONTEXT.get();
        if (ctx != null) {
            CONTEXT.set(new RequestContext(ctx.userId(), ctx.organizationId(), ctx.requestId(), ctx.email(), correlationId));
        }
    }

    /**
     * Get correlationId from current context.
     * @return correlationId or null
     */
    public static String getCorrelationId() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.correlationId() : null;
    }

    /**
     * Record holding the gateway request context data.
     */
    public record RequestContext(Integer userId, String organizationId, String requestId, String email, String correlationId) {
        /** Convenience constructor without correlationId (backwards compatible). */
        public RequestContext(Integer userId, String organizationId, String requestId, String email) {
            this(userId, organizationId, requestId, email, null);
        }
    }
}
