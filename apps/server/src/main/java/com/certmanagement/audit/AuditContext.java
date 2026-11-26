// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.OrgResolver;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Who acts and from where, for the rows written on this thread.
 *
 * <p>Inside a request it reads what the request already carries: the verified user and organization
 * from {@link GatewayRequestContext} (set from the JWT), the request and correlation ids
 * {@link RequestContextInterceptor} resolved, the client address it took from
 * {@link com.certmanagement.security.ClientAddressResolver}, the user agent, and the trace id. Nothing has to
 * be set for a request. Jobs and message consumers open an {@link AuditScope} instead, which takes
 * precedence until it is closed.
 */
public final class AuditContext {

    /** What a customer reads as the actor of something CertPing did itself. */
    public static final String SYSTEM_LABEL = "CertPing (automatic)";

    /** {@link RequestContextInterceptor}'s placeholder for an id it does not have. */
    private static final String UNKNOWN = "unknown";

    private static final ThreadLocal<Scoped> SCOPE = new ThreadLocal<>();

    private AuditContext() {
    }

    /**
     * Who acts.
     *
     * @param organizationId the organization the actor acts for; {@code null} for none
     * @param job            the job a {@link AuditActorType#SYSTEM} actor runs
     * @param superAdmin     a platform super admin, whose rows in another organization's trail are staff rows
     */
    public record Actor(AuditActorType type, Integer userId, Long organizationId, String job, String authMethod,
                        boolean superAdmin) {

        static Actor anonymous() {
            return new Actor(AuditActorType.ANONYMOUS, null, null, null, null, false);
        }

        static Actor system(String job, Long organizationId) {
            return new Actor(AuditActorType.SYSTEM, null, organizationId, job, null, false);
        }
    }

    /** Where the action came from: the client and the ids a customer can quote to support. */
    public record Origin(String ipAddress, String userAgent, String requestId, String correlationId, String traceId) {
    }

    /**
     * What an open {@link AuditScope} sets.
     *
     * @param client whether the rows keep the request's client and ids: a user scope does (the user acts
     *               from this request), a system scope does not (CertPing acts, from nowhere)
     */
    record Scoped(Actor actor, String requestId, String correlationId, boolean client) {
    }

    /** The actor of the open {@link AuditScope}, else the request's user, else anonymous. */
    public static Actor actor() {
        Scoped scoped = SCOPE.get();
        if (scoped != null) {
            return scoped.actor();
        }
        Integer userId = GatewayRequestContext.getUserId();
        if (userId == null) {
            return Actor.anonymous();
        }
        return new Actor(AuditActorType.USER, userId, parseOrganization(GatewayRequestContext.getOrganizationId()),
                null, null, OrgResolver.isSuperAdmin());
    }

    /**
     * Where the action came from. Inside a system {@link AuditScope} there is no client: a job's row
     * carries its correlation id and trace only. A user scope keeps the request's.
     */
    public static Origin origin() {
        Scoped scoped = SCOPE.get();
        if (scoped != null && !scoped.client()) {
            return new Origin(null, null, scoped.requestId(), scoped.correlationId(), currentTraceId());
        }
        String requestId = known(RequestContextInterceptor.getCurrentRequestId());
        if (requestId == null) {
            requestId = GatewayRequestContext.getRequestId();
        }
        String correlationId = known(RequestContextInterceptor.getCurrentCorrelationId());
        return new Origin(RequestContextInterceptor.getCurrentClientIp(), currentUserAgent(), requestId,
                correlationId, currentTraceId());
    }

    /** Opens a scope and returns the one it replaces, for {@link AuditScope#close()} to put back. */
    static Scoped push(Scoped scoped) {
        Scoped previous = SCOPE.get();
        SCOPE.set(scoped);
        return previous;
    }

    static void restore(Scoped previous) {
        if (previous == null) {
            SCOPE.remove();
        } else {
            SCOPE.set(previous);
        }
    }

    private static Long parseOrganization(String organizationId) {
        if (organizationId == null || organizationId.isBlank()) {
            return null;
        }
        try {
            return Long.valueOf(organizationId.trim());
        } catch (NumberFormatException notANumber) {
            return null;
        }
    }

    private static String known(String id) {
        return id == null || id.isBlank() || UNKNOWN.equals(id) ? null : id;
    }

    private static String currentUserAgent() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servlet) {
            HttpServletRequest request = servlet.getRequest();
            return request.getHeader("User-Agent");
        }
        return null;
    }

    private static String currentTraceId() {
        SpanContext span = Span.current().getSpanContext();
        return span.isValid() ? span.getTraceId() : null;
    }
}
