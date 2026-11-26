// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.slf4j.MDC;

/**
 * Sets the actor of the rows written on this thread until closed: CertPing for jobs, message consumers
 * and agent results ({@link #system}); a user the request has not authenticated yet for sign-in flows
 * ({@link #user}). Open it with try-with-resources; scopes nest, and closing one puts back
 * whatever was there before.
 *
 * <pre>{@code
 * try (AuditScope scope = AuditScope.system("trigger-renewals", organizationId)) {
 *     auditRecorder.record(AuditEvents.success(...));
 * }
 * }</pre>
 */
public final class AuditScope implements AutoCloseable {

    private final AuditContext.Scoped previous;
    private boolean closed;

    private AuditScope(AuditContext.Scoped scoped) {
        this.previous = AuditContext.push(scoped);
    }

    /**
     * CertPing acting as {@code job} for {@code organizationId} ({@code null} for a platform-wide job),
     * with the correlation and request ids the thread's MDC carries.
     */
    public static AuditScope system(String job, Long organizationId) {
        return system(job, organizationId, MDC.get("correlationId"));
    }

    /** As {@link #system(String, Long)}, with the correlation id of the work that triggered it. */
    public static AuditScope system(String job, Long organizationId, String correlationId) {
        return new AuditScope(new AuditContext.Scoped(AuditContext.Actor.system(job, organizationId),
                MDC.get("requestId"), correlationId, false));
    }

    /**
     * The user {@code userId} acting from this request, for the moments the request does not carry their
     * verified token: signing in (the token is being issued), a sign-in refused for their account, signing
     * out with an expired access token, and a password reset by emailed link. The rows keep the request's
     * client address, user agent and ids.
     *
     * @param organizationId the user's organization; {@code null} for platform staff, who have none
     * @param authMethod     how the session was or is being started ({@code LOCAL}, {@code SSO}, {@code SOCIAL})
     * @param superAdmin     the user is a platform super admin
     */
    public static AuditScope user(int userId, Long organizationId, String authMethod, boolean superAdmin) {
        return new AuditScope(new AuditContext.Scoped(new AuditContext.Actor(AuditActorType.USER, userId,
                organizationId, null, authMethod, superAdmin), null, null, true));
    }

    /**
     * Someone not identified, acting in {@code organizationId}'s trail without a client: a single sign-on
     * attempt that came through the organization's configuration but matched no member. Who called is unknown
     * until an assertion is validated, so the rows keep no client address or user agent; they keep the
     * request and correlation ids, which the person signing in can quote.
     */
    public static AuditScope anonymous(Long organizationId) {
        AuditContext.Origin origin = AuditContext.origin();
        return new AuditScope(new AuditContext.Scoped(new AuditContext.Actor(AuditActorType.ANONYMOUS, null,
                organizationId, null, null, false), origin.requestId(), origin.correlationId(), false));
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            AuditContext.restore(previous);
        }
    }
}
