// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.Metrics;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Writes the failure rows {@link AuditFailure} declares: from {@link AuditFailureAspect} for a call the
 * method was entered for, and from {@code GlobalExceptionHandler} for a request refused before it was (a
 * {@code @Valid} body, a bad parameter). One request records at most one failure: the first marks the
 * request, so the exception handler does not record again what the aspect already did.
 *
 * <p>Rows are queued for the async writer ({@link AuditRecorder#recordFailure}): the refusal is
 * answered whether or not its row could be written, and a request thread never holds a second pool
 * connection for it. Nothing here throws to the caller: a failure to build or queue a row is counted
 * ({@code certping_audit_failure_unrecorded_total}) and logged with its type only. A request whose success
 * row already committed records no failure ({@link AuditRecorder}): one request, one outcome.
 *
 * <p>Refusals are cheap to cause, so they are throttled before they reach the shared queue; every row held
 * back is counted in {@code certping_audit_throttled_total{event}}:
 * <ol>
 *   <li>a repeat (the same actor, event, target and reason) is written once a minute;</li>
 *   <li>one actor writes at most {@value #ACTOR_ROWS_PER_MINUTE} failure rows a minute;</li>
 *   <li>one organization (or the platform, for staff) writes at most {@value #ORGANIZATION_ROWS_PER_MINUTE}
 *       a minute. This is the tenant fairness ceiling: the async writer drains far more than that, so one
 *       organization's refusals cannot fill the bounded queue other organizations' rows go through. A
 *       ceiling at the source was chosen over a second queue: it needs no second writer thread or shutdown
 *       drain, and it bounds exactly the rows a caller can provoke.</li>
 * </ol>
 * The throttles are per pod (Caffeine, bounded to {@value #MAX_KEYS} keys each), so the totals across the
 * cluster are bounded by the pod count.
 */
@Slf4j
@Component
public class AuditFailures {

    /** The request attribute that marks a request whose failure row was written. */
    static final String RECORDED = AuditFailures.class.getName() + ".RECORDED";
    static final String UNRECORDED_METRIC = "certping.audit.failure.unrecorded";
    static final String THROTTLED_METRIC = "certping.audit.throttled";
    static final Duration REPEAT_EVERY = Duration.ofMinutes(1);
    static final int ACTOR_ROWS_PER_MINUTE = 30;
    static final int ORGANIZATION_ROWS_PER_MINUTE = 300;
    static final int MAX_KEYS = 50_000;

    private static final Pattern NUMBER = Pattern.compile("^[0-9]{1,18}$");
    private static final ParameterNameDiscoverer PARAMETER_NAMES = new DefaultParameterNameDiscoverer();
    private static final SpelExpressionParser PARSER = new SpelExpressionParser();

    private final AuditRecorder recorder;
    private final Clock clock;
    private final Map<String, Expression> expressions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Boolean> recentRepeats;
    /** Rows written per actor and per organization, keyed by the minute they were written in. */
    private final ConcurrentMap<String, AtomicInteger> perMinute;

    public AuditFailures(AuditRecorder recorder, Clock clock) {
        this.recorder = recorder;
        this.clock = clock;
        this.recentRepeats = Caffeine.newBuilder()
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .expireAfterWrite(REPEAT_EVERY)
                .maximumSize(MAX_KEYS)
                .<String, Boolean>build()
                .asMap();
        this.perMinute = Caffeine.newBuilder()
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .expireAfterWrite(Duration.ofMinutes(2))
                .maximumSize(MAX_KEYS)
                .<String, AtomicInteger>build()
                .asMap();
    }

    /** The call of {@code method} with {@code arguments} failed for {@code reason}. */
    void record(AuditFailure failure, Method method, Object[] arguments, AuditReason reason) {
        if (succeeded() || alreadyRecorded()) {
            return;
        }
        try {
            EvaluationContext context = new MethodBasedEvaluationContext(null, method, arguments, PARAMETER_NAMES);
            write(failure, context, reason);
        } catch (RuntimeException e) {
            unrecorded(failure, e);
        }
    }

    /**
     * A request refused before its handler method ran, reported by the exception handler: recorded when
     * the method declares {@link AuditFailure} and nothing was recorded for the request yet. The
     * expressions see the path variables only.
     */
    public void recordRefusedRequest(HttpServletRequest request, Throwable refusal) {
        if (request == null || request.getAttribute(RECORDED) != null
                || request.getAttribute(AuditRecorder.SUCCEEDED) != null) {
            return;
        }
        AuditFailure failure = null;
        try {
            if (!(request.getAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE) instanceof HandlerMethod handler)) {
                return;
            }
            failure = AnnotatedElementUtils.findMergedAnnotation(handler.getMethod(), AuditFailure.class);
            if (failure == null) {
                return;
            }
            request.setAttribute(RECORDED, Boolean.TRUE);
            SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
            if (request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE) instanceof Map<?, ?> variables) {
                variables.forEach((name, value) -> context.setVariable(String.valueOf(name), value));
            }
            write(failure, context, AuditReasons.of(refusal));
        } catch (RuntimeException e) {
            unrecorded(failure, e);
        }
    }

    private void write(AuditFailure failure, EvaluationContext context, AuditReason reason) {
        AuditEventType type = failure.instead().length > 0
                && Boolean.TRUE.equals(evaluate(failure.insteadWhen(), context)) ? failure.instead()[0] : failure.value();
        AuditSubject.AuditSubjectBuilder subject = AuditSubject.builder();
        Object target = evaluate(failure.target(), context);
        if (target != null) {
            String ref = String.valueOf(target).trim();
            if (NUMBER.matcher(ref).matches()) {
                subject.resourceId(Long.valueOf(ref)).resourceRef(ref);
            } else if (!ref.isEmpty()) {
                subject.resourceRef(ref);
            }
        }
        Object name = evaluate(failure.name(), context);
        if (name != null) {
            subject.name(String.valueOf(name));
        }
        Object domain = evaluate(failure.domain(), context);
        if (domain != null) {
            subject.domain(String.valueOf(domain));
        }
        // Only a super admin acts on another organization's resources: anyone else's failure lands in their own
        // trail, whatever organization the refused request named, so no one can write into another's trail.
        AuditContext.Actor actor = AuditContext.actor();
        Long organizationId = actor.superAdmin() ? organization(evaluate(failure.organization(), context)) : null;
        subject.organizationId(organizationId);
        boolean noTrail = organizationId == null && actor.organizationId() == null;
        AuditSubject built = subject.build();
        AuditEventRow row;
        if (type.visibility() == AuditVisibility.INTERNAL) {
            row = AuditEvents.internalFailure(type, built, reason);
        } else {
            // A caller with no organization (platform staff) acting on no organization's resource: there is no
            // customer trail to write into, so the attempt is the platform's record only.
            row = noTrail ? AuditEvents.platformOnlyFailure(type, built, reason) : AuditEvents.failure(type, built, reason);
        }
        if (admitted(row)) {
            recorder.recordFailure(row);
        }
    }

    /** Whether {@code row} passes the repeat, per-actor and per-organization throttles; counts it if not. */
    private boolean admitted(AuditEventRow row) {
        String actor = row.actorType() + ":" + (row.actorUserId() != null ? row.actorUserId()
                : row.ipAddress() != null ? row.ipAddress() : "unknown");
        String repeat = actor + "|" + row.event() + "|" + row.resourceRef() + "|" + row.errorCode();
        boolean admitted = recentRepeats.putIfAbsent(repeat, Boolean.TRUE) == null
                && withinMinuteCap("actor:" + actor, ACTOR_ROWS_PER_MINUTE)
                && withinMinuteCap("org:" + (row.organizationId() == null ? "platform" : row.organizationId()),
                        ORGANIZATION_ROWS_PER_MINUTE);
        if (!admitted) {
            Metrics.counter(THROTTLED_METRIC, "event", row.event()).increment();
        }
        return admitted;
    }

    private boolean withinMinuteCap(String key, int cap) {
        long minute = clock.millis() / 60_000L;
        return perMinute.computeIfAbsent(key + "|" + minute, k -> new AtomicInteger()).incrementAndGet() <= cap;
    }

    private Object evaluate(String expression, EvaluationContext context) {
        if (expression == null || expression.isBlank()) {
            return null;
        }
        try {
            return expressions.computeIfAbsent(expression, PARSER::parseExpression).getValue(context);
        } catch (RuntimeException unknown) {
            // A path variable the refused request did not carry, or a null on the way: the row is kept
            // without it.
            return null;
        }
    }

    private static Long organization(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        String text = String.valueOf(value).trim();
        return NUMBER.matcher(text).matches() ? Long.valueOf(text) : null;
    }

    /** Whether this request's success row committed: a later failure of it is not a second outcome. */
    private static boolean succeeded() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes != null
                && attributes.getAttribute(AuditRecorder.SUCCEEDED, RequestAttributes.SCOPE_REQUEST) != null;
    }

    /** Whether this request's failure was recorded already; marks it recorded otherwise. */
    private static boolean alreadyRecorded() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return false;
        }
        if (attributes.getAttribute(RECORDED, RequestAttributes.SCOPE_REQUEST) != null) {
            return true;
        }
        attributes.setAttribute(RECORDED, Boolean.TRUE, RequestAttributes.SCOPE_REQUEST);
        return false;
    }

    private static void unrecorded(AuditFailure failure, RuntimeException e) {
        String event = failure == null ? "unknown" : failure.value().key();
        Metrics.counter(UNRECORDED_METRIC, "event", event).increment();
        log.warn("[AuditFailures] could not record the failure of {} ({})", event, e.getClass().getSimpleName());
    }
}
