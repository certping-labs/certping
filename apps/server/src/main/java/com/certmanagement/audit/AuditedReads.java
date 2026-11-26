// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.Metrics;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Writes the sensitive-read rows {@link AuditedRead} declares (the trail's Access view), grouped: the first read
 * of a target by an actor writes a row, and the same actor reading the same target in the same organization's
 * trail writes nothing more for {@value #GROUP_MINUTES} minutes. A different target, actor or organization is a
 * new row at once.
 *
 * <p>The grouping is per pod (Caffeine, at most {@value #MAX_KEYS} keys, the oldest evicted first), so across
 * the cluster a burst of reads leaves at most one row per pod; the rows held back are counted in
 * {@code certping_audit_read_grouped_total{event}}. Rows go through the bounded async writer
 * ({@link AuditRecorder#recordAsync}): a read never waits for its row, and nothing here throws to the caller. A
 * row that cannot be built is counted ({@code certping_audit_read_unrecorded_total}) and logged with its type
 * only.
 */
@Slf4j
@Component
public class AuditedReads {

    static final long GROUP_MINUTES = 15;
    static final Duration GROUP_FOR = Duration.ofMinutes(GROUP_MINUTES);
    static final int MAX_KEYS = 50_000;
    static final String GROUPED_METRIC = "certping.audit.read.grouped";
    static final String UNRECORDED_METRIC = "certping.audit.read.unrecorded";

    private static final Pattern NUMBER = Pattern.compile("^[0-9]{1,18}$");
    private static final ParameterNameDiscoverer PARAMETER_NAMES = new DefaultParameterNameDiscoverer();
    private static final SpelExpressionParser PARSER = new SpelExpressionParser();

    private final AuditRecorder recorder;
    private final Map<String, Expression> expressions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Boolean> recent;

    public AuditedReads(AuditRecorder recorder, Clock clock) {
        this.recorder = recorder;
        this.recent = Caffeine.newBuilder()
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .expireAfterWrite(GROUP_FOR)
                .maximumSize(MAX_KEYS)
                .<String, Boolean>build()
                .asMap();
    }

    /** The call of {@code method} with {@code arguments} read what {@code read} names. */
    void record(AuditedRead read, Method method, Object[] arguments) {
        try {
            EvaluationContext context = new MethodBasedEvaluationContext(null, method, arguments, PARAMETER_NAMES);
            AuditSubject.AuditSubjectBuilder subject = AuditSubject.builder();
            Object target = evaluate(read.target(), context);
            if (target != null) {
                String ref = String.valueOf(target).trim();
                if (NUMBER.matcher(ref).matches()) {
                    subject.resourceId(Long.valueOf(ref)).resourceRef(ref);
                } else if (!ref.isEmpty()) {
                    subject.resourceRef(ref);
                }
            }
            // Only a super admin reads another organization's data: anyone else's read lands in their own trail.
            AuditContext.Actor actor = AuditContext.actor();
            Long organizationId = actor.superAdmin() ? organization(evaluate(read.organization(), context)) : null;
            subject.organizationId(organizationId);
            boolean noTrail = organizationId == null && actor.organizationId() == null;
            AuditEventRow row = noTrail ? AuditEvents.platformOnly(read.value(), subject.build())
                    : AuditEvents.success(read.value(), subject.build());
            if (firstInGroup(row)) {
                recorder.recordAsync(row);
            }
        } catch (RuntimeException e) {
            Metrics.counter(UNRECORDED_METRIC, "event", read.value().key()).increment();
            log.warn("[AuditedReads] could not record the read {} ({})", read.value().key(),
                    e.getClass().getSimpleName());
        }
    }

    /**
     * A platform administrator (a super admin) read {@code organizationId}'s trail from the platform view: a staff row in
     * that trail, which the customer reads as "Platform administrator", grouped as the reads above are. With no
     * organization (every organization's trail) the row is internal. Never throws, never waits.
     */
    public void staffRead(AuditEventType type, Long organizationId) {
        try {
            AuditEventRow row = staffRow(type, organizationId, AuditSubject.NONE);
            if (firstInGroup(row)) {
                recorder.recordAsync(row);
            }
        } catch (RuntimeException e) {
            Metrics.counter(UNRECORDED_METRIC, "event", type.key()).increment();
            log.warn("[AuditedReads] could not record the staff read {} ({})", type.key(), e.getClass().getSimpleName());
        }
    }

    /**
     * A platform administrator is about to export {@code organizationId}'s trail: the staff row is written now, in a
     * transaction of its own, before any row of the export is read. Exports are never grouped: each one is on
     * record, with its own range and row count (reads are, as above).
     *
     * @return {@code false} when the row could not be written: the export must not go ahead
     */
    public boolean staffExport(AuditEventType type, Long organizationId, AuditSubject subject) {
        AuditEventRow row;
        try {
            row = staffRow(type, organizationId, subject);
        } catch (RuntimeException e) {
            Metrics.counter(UNRECORDED_METRIC, "event", type.key()).increment();
            log.warn("[AuditedReads] could not build the staff export {} ({})", type.key(), e.getClass().getSimpleName());
            return false;
        }
        return recorder.recordDurable(row);
    }

    private static AuditEventRow staffRow(AuditEventType type, Long organizationId, AuditSubject subject) {
        AuditSubject inTrail = subject.toBuilder().organizationId(organizationId).build();
        return organizationId == null ? AuditEvents.platformOnly(type, inTrail) : AuditEvents.success(type, inTrail);
    }

    /** Whether {@code row} opens a new group; counts it as grouped if not. */
    private boolean firstInGroup(AuditEventRow row) {
        boolean first = recent.putIfAbsent(groupKey(row), Boolean.TRUE) == null;
        if (!first) {
            Metrics.counter(GROUPED_METRIC, "event", row.event()).increment();
        }
        return first;
    }

    private static String groupKey(AuditEventRow row) {
        String actor = row.actorType() + ":" + Objects.toString(row.actorUserId(), "-");
        return (row.organizationId() == null ? "platform" : row.organizationId()) + "|" + actor + "|"
                + row.event() + "|" + Objects.toString(row.resourceRef(), "-");
    }

    private Object evaluate(String expression, EvaluationContext context) {
        if (expression == null || expression.isBlank()) {
            return null;
        }
        try {
            return expressions.computeIfAbsent(expression, PARSER::parseExpression).getValue(context);
        } catch (RuntimeException unknown) {
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
}
