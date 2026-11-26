// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import io.micrometer.core.instrument.Metrics;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Builds rows from the catalog: the actor and origin come from the current {@link AuditContext},
 * everything else from the {@link AuditEventType} and the {@link AuditSubject}.
 *
 * <p>A failure takes an {@link AuditReason}, never a message or an exception, so nothing internal can
 * be written as a failure's cause. What else a row may carry is decided by its catalog entry:
 * <ul>
 *   <li>attributes not on the event's allow-list are dropped and counted
 *       ({@code certping_audit_attribute_dropped_total}); internal-only attributes (an operator's note)
 *       are kept on internal rows and dropped from customer rows;</li>
 *   <li>changed fields not on it are dropped and counted
 *       ({@code certping_audit_field_rejected_total{field="changes"}}); a member's personal fields (email,
 *       name) and secret fields declared name-only are kept by name only, with no value;</li>
 *   <li>subject text shaped like a secret (PEM, SAS, JWT) is redacted before the templates render, so it
 *       reaches neither the summary nor the resource name;</li>
 *   <li>a member target's {@code resource_ref} must be the numeric user id; anything else (an email, a
 *       name) is nulled and counted ({@code certping_audit_field_rejected_total{field="resource_ref"}}),
 *       and the row is kept;</li>
 *   <li>a customer row with no organization has no trail to land in: it is kept as an internal row and
 *       counted ({@code certping_audit_downgraded_total{reason="no_org"}}).</li>
 * </ul>
 *
 * <p>Pass the row to {@link AuditRecorder}: {@code record} for a success in the caller's transaction,
 * {@code recordFailure} for a failure, {@code recordAsync} for reads and internal rows.
 */
@Slf4j
public final class AuditEvents {

    static final String ATTRIBUTE_DROPPED_METRIC = "certping.audit.attribute.dropped";
    static final String FIELD_REJECTED_METRIC = "certping.audit.field.rejected";
    static final String DOWNGRADED_METRIC = "certping.audit.downgraded";

    private static final Pattern USER_ID = Pattern.compile("^[0-9]{1,18}$");

    private AuditEvents() {
    }

    /** A customer event that happened. */
    public static AuditEventRow success(AuditEventType type, AuditSubject subject) {
        return build(requireVisibility(type, AuditVisibility.CUSTOMER), subject, AuditOutcome.SUCCESS, null);
    }

    /** A customer event that was attempted and failed, for {@code reason}. */
    public static AuditEventRow failure(AuditEventType type, AuditSubject subject, AuditReason reason) {
        return build(requireVisibility(type, AuditVisibility.CUSTOMER), subject, AuditOutcome.FAILURE,
                Objects.requireNonNull(reason, "reason"));
    }

    /** A customer event that was started and completes later, e.g. once an agent reports back. */
    public static AuditEventRow pending(AuditEventType type, AuditSubject subject) {
        return build(requireVisibility(type, AuditVisibility.CUSTOMER), subject, AuditOutcome.PENDING, null);
    }

    /** An internal action that happened, for the platform's eyes only. */
    public static AuditEventRow internal(AuditEventType type, AuditSubject subject) {
        return build(requireVisibility(type, AuditVisibility.INTERNAL), subject, AuditOutcome.SUCCESS, null);
    }

    /** An internal action that failed, for {@code reason}. */
    public static AuditEventRow internalFailure(AuditEventType type, AuditSubject subject, AuditReason reason) {
        return build(requireVisibility(type, AuditVisibility.INTERNAL), subject, AuditOutcome.FAILURE,
                Objects.requireNonNull(reason, "reason"));
    }

    /**
     * A customer event kept for the platform's eyes only: a platform staff member's own sign-in or password
     * change (staff belong to no customer's trail), or a sign-in attempt for an identifier no account has.
     * The row keeps the event's key and sentence but is internal; a super admin's row is a staff row.
     */
    public static AuditEventRow platformOnly(AuditEventType type, AuditSubject subject) {
        return build(requireVisibility(type, AuditVisibility.CUSTOMER), subject, AuditOutcome.SUCCESS, null,
                AuditContext.actor(), AuditContext.origin(), Instant.now(), Mode.PLATFORM_ONLY);
    }

    /** {@link #platformOnly} for an attempt that failed, for {@code reason}. */
    public static AuditEventRow platformOnlyFailure(AuditEventType type, AuditSubject subject, AuditReason reason) {
        return build(requireVisibility(type, AuditVisibility.CUSTOMER), subject, AuditOutcome.FAILURE,
                Objects.requireNonNull(reason, "reason"), AuditContext.actor(), AuditContext.origin(), Instant.now(),
                Mode.PLATFORM_ONLY);
    }

    /**
     * An internal row for an actor and origin captured earlier, where the current context no longer holds them
     * (a request row written once the request has completed).
     */
    public static AuditEventRow internalAs(AuditEventType type, AuditSubject subject, AuditReason reason,
                                           AuditContext.Actor actor, AuditContext.Origin origin) {
        requireVisibility(type, AuditVisibility.INTERNAL);
        return build(type, subject, reason == null ? AuditOutcome.SUCCESS : AuditOutcome.FAILURE, reason, actor,
                origin, Instant.now(), Mode.CURRENT);
    }

    /** How a row is being built: for the current request or job, or platform-only. */
    private enum Mode { CURRENT, PLATFORM_ONLY }

    private static AuditEventRow build(AuditEventType type, AuditSubject given, AuditOutcome outcome,
                                       AuditReason reason) {
        return build(type, given, outcome, reason, AuditContext.actor(), AuditContext.origin(), Instant.now(),
                Mode.CURRENT);
    }

    private static AuditEventRow build(AuditEventType type, AuditSubject given, AuditOutcome outcome,
                                       AuditReason reason, AuditContext.Actor actor, AuditContext.Origin origin,
                                       Instant occurredAt, Mode mode) {
        AuditSubject subject = redactSecretValues(given == null ? AuditSubject.NONE : given);
        Long organizationId = subject.organizationId() != null ? subject.organizationId() : actor.organizationId();
        // A member's name is never stored: the summary keeps "a member" and is rendered again when read.
        AuditSubject stored = type.rendersTargetWhenRead() ? subject.toBuilder().name(null).build() : subject;
        AuditVisibility visibility = mode == Mode.PLATFORM_ONLY ? AuditVisibility.INTERNAL : type.visibility();
        if (visibility == AuditVisibility.CUSTOMER && organizationId == null) {
            Metrics.counter(DOWNGRADED_METRIC, "reason", "no_org", "event", type.key()).increment();
            log.warn("[Audit] {} has no organization; kept as an internal row", type.key());
            visibility = AuditVisibility.INTERNAL;
        }

        return AuditEventRow.builder()
                .occurredAt(occurredAt)
                .visibility(visibility)
                .event(type.key())
                .category(type.category().name())
                .featureKey(type.featureKey())
                .organizationId(organizationId)
                .actorType(actor.type())
                .actorUserId(actor.userId())
                .actorLabel(actor.type() == AuditActorType.SYSTEM ? AuditContext.SYSTEM_LABEL : null)
                .actorJob(actor.job())
                .actorStaff(isStaff(actor, organizationId)
                        || (mode == Mode.PLATFORM_ONLY && actor.type() == AuditActorType.USER && actor.superAdmin()))
                .authMethod(actor.authMethod())
                .action(type.action())
                .resourceType(type.resourceType().name())
                .resourceId(subject.resourceId())
                .resourceRef(resourceRef(type, subject.resourceRef()))
                .resourceName(type.rendersTargetWhenRead() ? null : firstNonBlank(subject.name(), subject.domain()))
                .outcome(outcome)
                .errorCode(reason == null ? null : reason.code())
                .summary(outcome == AuditOutcome.FAILURE ? type.failure(stored) : type.summary(stored))
                .details(new AuditDetails(allowedChanges(type, subject.changes()),
                        allowedAttributes(type, subject.attributes(), visibility)))
                .ipAddress(origin.ipAddress())
                .userAgent(origin.userAgent())
                .requestId(origin.requestId())
                .correlationId(origin.correlationId())
                .traceId(origin.traceId())
                .build();
    }

    /**
     * Whether the action is CertPing staff's in the trail it lands in: its user was a super admin when they acted,
     * in any organization's trail, their own included. Staffness belongs to the action, decided from the context it
     * ran in. Nothing else makes a row staff: not being a member of another organization, nor an account acting for
     * no organization (one signing up, or accepting an invitation, writes into the new trail as itself).
     */
    private static boolean isStaff(AuditContext.Actor actor, Long organizationId) {
        return actor.type() == AuditActorType.USER && organizationId != null && actor.superAdmin();
    }

    /**
     * The subject's free-text fields with any value shaped like a secret (a pasted PEM block, a SAS
     * token, a JWT) replaced, before a template interpolates them into the summary or resource name.
     */
    private static AuditSubject redactSecretValues(AuditSubject subject) {
        String name = redacted(subject.name());
        String provider = redacted(subject.provider());
        String domain = redacted(subject.domain());
        String format = redacted(subject.format());
        String resourceRef = redacted(subject.resourceRef());
        if (name == subject.name() && provider == subject.provider() && domain == subject.domain()
                && format == subject.format() && resourceRef == subject.resourceRef()) {
            return subject;
        }
        return subject.toBuilder().name(name).provider(provider).domain(domain).format(format)
                .resourceRef(resourceRef).build();
    }

    private static String redacted(String value) {
        return value != null && AuditSanitizer.isSecretValue(value) ? AuditSanitizer.REDACTED : value;
    }

    /** A member target is referenced by its numeric id only, never by an email or a name. */
    private static String resourceRef(AuditEventType type, String ref) {
        if (ref == null || !type.rendersTargetWhenRead() || USER_ID.matcher(ref).matches()) {
            return ref;
        }
        rejected(type, "resource_ref");
        return null;
    }

    private static List<AuditChange> allowedChanges(AuditEventType type, List<AuditChange> changes) {
        List<AuditChange> allowed = new ArrayList<>(changes.size());
        for (AuditChange change : changes) {
            if (type.personalChanges().contains(change.field()) || type.nameOnly().contains(change.field())) {
                allowed.add(new AuditChange(change.field(), null, null));
            } else if (type.allowedChanges().contains(change.field())) {
                allowed.add(change);
            } else {
                rejected(type, "changes");
                log.warn("[Audit] dropped change of {} not allowed on {}", change.field(), type.key());
            }
        }
        return allowed;
    }

    private static void rejected(AuditEventType type, String field) {
        Metrics.counter(FIELD_REJECTED_METRIC, "field", field, "event", type.key()).increment();
    }

    private static Map<String, String> allowedAttributes(AuditEventType type, Map<String, String> attributes,
                                                         AuditVisibility visibility) {
        Map<String, String> allowed = new LinkedHashMap<>();
        attributes.forEach((name, value) -> {
            if (type.internalOnlyAttributes().contains(name)) {
                // Kept for the platform; a customer row of the event never carries it.
                if (visibility == AuditVisibility.INTERNAL) {
                    allowed.put(name, value);
                }
            } else if (type.nameOnly().contains(name)) {
                allowed.put(name, null);
            } else if (type.allowedAttributes().contains(name)) {
                allowed.put(name, value);
            } else {
                Metrics.counter(ATTRIBUTE_DROPPED_METRIC, "event", type.key()).increment();
                log.warn("[Audit] dropped attribute {} not allowed on {}", name, type.key());
            }
        });
        return allowed;
    }

    private static AuditEventType requireVisibility(AuditEventType type, AuditVisibility visibility) {
        Objects.requireNonNull(type, "type");
        if (type.visibility() != visibility) {
            throw new IllegalArgumentException(type.key() + " is " + type.visibility() + ", not " + visibility);
        }
        return type;
    }

    private static String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        return second != null && !second.isBlank() ? second : null;
    }
}
