// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.TransportMessage;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.MessageSender;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Queue-level retry via {@code ScheduledEnqueueTime}.
 *
 * <p>When ACS (or any downstream provider) throws a rate-limit / retry-after
 * signal, the notifier's listener hands the receive-context to this service.
 * We clone the message body, stamp {@code RetryCount + LastRetry*} application
 * properties, set a future-dated {@code ScheduledEnqueueTime}, send the copy
 * back to the notifications channel, and settle the original with
 * {@code complete()}. The server's queue then holds the copy invisibly until
 * the schedule time and delivers it as a normal message.
 *
 * <p>Two rules matter here:
 * <ul>
 *   <li>The notifier routes each message to a handler on its
 *       {@code notificationType} property. We must therefore copy the
 *       original {@code notificationType} application property onto the retry
 *       so that it reaches the same handler again.</li>
 *   <li>The {@code messageId} of the retry is <b>not</b> preserved — the server
 *       assigns a fresh one. Downstream idempotency now relies on ACS's own
 *       operation-id semantics and application-level guards (audit rows are
 *       per-attempt).</li>
 * </ul>
 */
@Slf4j
@Service
public class ScheduledRetryService {

    static final String PROP_RETRY_COUNT = "RetryCount";
    static final String PROP_LAST_RETRY_REASON = "LastRetryReason";
    static final String PROP_LAST_RETRY_DETAIL = "LastRetryDetail";
    static final String PROP_LAST_RETRY_AT = "LastRetryAt";
    static final String PROP_LAST_RETRY_AFTER_SEC = "LastRetryAfterSec";
    static final String PROP_NOTIFICATION_TYPE = "notificationType";
    /** When the first retry of a deliver-once message was scheduled, carried on every later copy. */
    static final String PROP_FIRST_RETRY_AT = "FirstRetryAt";
    private static final int MAX_DETAIL_LEN = 500;

    /** Past the retry budget, a deliver-once email is tried again this often. */
    static final Duration UNDELIVERED_EVERY = Duration.ofHours(1);

    private final MessageSender notificationsSenderClient;
    private final int maxScheduledRetries;
    private final Duration hardCap;
    private final Duration undeliveredMaxAge;

    public ScheduledRetryService(
            MessageSender notificationsSenderClient,
            @Value("${notifier.retry.max-scheduled-retries:10}") int maxScheduledRetries,
            @Value("${notifier.retry.hard-cap-hours:24}") long hardCapHours,
            @Value("${notifier.retry.deliver-once-max-age:P7D}") Duration undeliveredMaxAge) {
        this.notificationsSenderClient = notificationsSenderClient;
        this.maxScheduledRetries = maxScheduledRetries;
        this.hardCap = Duration.ofHours(hardCapHours);
        this.undeliveredMaxAge = undeliveredMaxAge;
    }

    /** How a retry copy is budgeted: by count, or, for a deliver-once email, until it is too old to matter. */
    enum Policy { STANDARD, UNTIL_DELIVERED }

    /** One future-dated copy of (part of) the message's body. */
    record RetryCopy(Duration delay, String reasonCode, String reasonMessage, String bodyJson, Policy policy) {
    }

    /** What happened to one copy. */
    enum Scheduled {
        /** Sent within the retry budget. */
        WITHIN_BUDGET,
        /** A deliver-once copy sent past the budget, hourly: the email is still undelivered. */
        PAST_BUDGET,
        /** Not sent: out of budget, or a deliver-once email older than its maximum age. */
        REFUSED,
        /** Not sent: the server refused it. */
        FAILED
    }

    public int getMaxScheduledRetries() {
        return maxScheduledRetries;
    }

    public int currentRetryCount(InboundMessage message) {
        Object raw = message.getApplicationProperties().get(PROP_RETRY_COUNT);
        if (raw instanceof Number n) {
            return n.intValue();
        }
        if (raw instanceof String s) {
            try {
                return Integer.parseInt(s);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    /**
     * Reschedule {@code ctx}'s message for future delivery, then complete the
     * original. Returns {@code true} if the retry was successfully scheduled
     * and the original was settled; {@code false} if either operation failed
     * (caller should then fall back to {@code abandon()} or {@code deadLetter}).
     *
     * <p>If the caller-supplied {@code delay} exceeds {@link #hardCap}, we clamp
     * to the cap. If {@code currentRetryCount + 1 > maxScheduledRetries}, we
     * refuse to schedule and return {@code false} — the caller should
     * dead-letter.
     */
    public boolean scheduleRetry(InboundContext ctx,
                                 Duration delay,
                                 String reasonCode,
                                 String reasonMessage) {
        return scheduleRetry(ctx, delay, reasonCode, reasonMessage, null);
    }

    /**
     * Variant that lets the caller substitute a different message body for the
     * retry. Used when a batch had some events succeed and some fail with
     * retryable errors — the caller passes in a JSON list containing only the
     * failed subset, so the already-DELIVERED events don't get re-sent and
     * users don't receive duplicate emails.
     *
     * <p>If {@code replacementBodyJson} is null the body is copied verbatim
     * from the original (same as the no-arg overload).
     */
    public boolean scheduleRetry(InboundContext ctx,
                                 Duration delay,
                                 String reasonCode,
                                 String reasonMessage,
                                 String replacementBodyJson) {
        List<Scheduled> outcome = scheduleRetries(ctx,
                List.of(new RetryCopy(delay, reasonCode, reasonMessage, replacementBodyJson, Policy.STANDARD)));
        return outcome.get(0) == Scheduled.WITHIN_BUDGET;
    }

    /**
     * Sends copies in order. A refused copy has exhausted its own budget; a later copy can still be
     * scheduled. The original is completed once all eligible copies were sent, so a refused standard
     * copy cannot cause a delivered-once copy to be scheduled again on redelivery.
     */
    public List<Scheduled> scheduleRetries(InboundContext ctx, List<RetryCopy> copies) {
        InboundMessage original = ctx.getMessage();
        List<Scheduled> outcomes = new ArrayList<>(copies.size());
        for (RetryCopy copy : copies) {
            if (outcomes.contains(Scheduled.FAILED)) {
                outcomes.add(Scheduled.FAILED);
            } else {
                outcomes.add(schedule(original, copy));
            }
        }
        boolean hasSentCopy = outcomes.stream().anyMatch(o -> o == Scheduled.WITHIN_BUDGET || o == Scheduled.PAST_BUDGET);
        if (hasSentCopy && !outcomes.contains(Scheduled.FAILED)) {
            try {
                ctx.complete();
            } catch (Exception e) {
                log.warn("ScheduledRetry sent its copies but could not complete the original; it will be redelivered: {}",
                        e.getMessage(), e);
            }
        }
        return outcomes;
    }

    private Scheduled schedule(InboundMessage original, RetryCopy copy) {
        String reasonCode = copy.reasonCode();
        String replacementBodyJson = copy.bodyJson();
        Duration delay = copy.delay();
        Instant now = Instant.now();
        Instant firstRetryAt = firstRetryAt(original, now);
        int nextRetryCount = currentRetryCount(original) + 1;
        boolean pastBudget = nextRetryCount > maxScheduledRetries;
        if (pastBudget && copy.policy() == Policy.STANDARD) {
            log.warn("ScheduledRetry refused: nextRetryCount {} > maxScheduledRetries {} (reason={})",
                    nextRetryCount, maxScheduledRetries, reasonCode);
            return Scheduled.REFUSED;
        }
        if (copy.policy() == Policy.UNTIL_DELIVERED && !now.isBefore(firstRetryAt.plus(undeliveredMaxAge))) {
            log.warn("ScheduledRetry refused: a deliver-once email first retried at {} is older than {} (reason={})",
                    firstRetryAt, undeliveredMaxAge, reasonCode);
            return Scheduled.REFUSED;
        }
        if (pastBudget && delay.compareTo(UNDELIVERED_EVERY) < 0) {
            delay = UNDELIVERED_EVERY;
        }
        try {
            Duration effectiveDelay = delay;
            if (effectiveDelay.compareTo(hardCap) > 0) {
                log.warn("ScheduledRetry delay {} exceeds hard cap {} — clamping (reason={})",
                        effectiveDelay, hardCap, reasonCode);
                effectiveDelay = hardCap;
            }

            // Body: caller-supplied when only a subset of the batch failed,
            // otherwise verbatim. messageId is NOT preserved either way — the
            // server assigns a fresh one. See class javadoc for the
            // idempotency implications.
            TransportMessage retry = replacementBodyJson != null
                    ? new TransportMessage(MessageBody.fromString(replacementBodyJson))
                    : new TransportMessage(original.getBody());

            // Copy all existing application properties (including
            // notificationType, which routes the copy to the same handler),
            // then overwrite the retry-tracking ones.
            Map<String, Object> props = retry.getApplicationProperties();
            props.putAll(original.getApplicationProperties());
            props.put(PROP_RETRY_COUNT, nextRetryCount);
            props.put(PROP_LAST_RETRY_REASON, reasonCode);
            props.put(PROP_LAST_RETRY_DETAIL, truncate(copy.reasonMessage(), MAX_DETAIL_LEN));
            props.put(PROP_LAST_RETRY_AT, now.toString());
            props.put(PROP_LAST_RETRY_AFTER_SEC, effectiveDelay.toSeconds());
            props.put(PROP_FIRST_RETRY_AT, firstRetryAt.toString());

            // Preserve correlationId so the retry lines up in traces with the
            // original attempt.
            if (original.getCorrelationId() != null) {
                retry.setCorrelationId(original.getCorrelationId());
            }

            OffsetDateTime scheduledFor = OffsetDateTime.now(ZoneOffset.UTC).plus(effectiveDelay);
            retry.setScheduledEnqueueTime(scheduledFor);

            // The copy is sent before the original is settled. If complete() then fails, the lock
            // expires and the original is redelivered: at most one duplicate attempt, which a
            // deliver-once email's per-recipient claim absorbs.
            notificationsSenderClient.sendMessage(retry);

            log.info("ScheduledRetry retryCount={} reason={} delaySec={} scheduledEnqueueTime={}",
                    nextRetryCount, reasonCode, effectiveDelay.toSeconds(), scheduledFor);
            return pastBudget ? Scheduled.PAST_BUDGET : Scheduled.WITHIN_BUDGET;
        } catch (Exception e) {
            log.warn("ScheduledRetry failed (reason={}) — caller will fall back to abandon: {}",
                    reasonCode, e.getMessage(), e);
            return Scheduled.FAILED;
        }
    }

    /** The first retry's time from the message, or now for the first retry of this email. */
    private static Instant firstRetryAt(InboundMessage message, Instant now) {
        Object raw = message.getApplicationProperties().get(PROP_FIRST_RETRY_AT);
        if (raw == null) {
            return now;
        }
        try {
            return Instant.parse(String.valueOf(raw));
        } catch (DateTimeParseException e) {
            return now;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max);
    }
}
