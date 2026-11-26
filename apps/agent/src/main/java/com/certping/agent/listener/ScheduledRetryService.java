// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.TransportMessage;
import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.transport.MessageSender;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Re-enqueues a failed inbound message onto the agent's OWN inbound queue with a
 * {@code ScheduledEnqueueTime}, then completes the original — so the worker thread is freed
 * immediately instead of blocking on an upstream wait, such as a Let's Encrypt rate limit.
 *
 * <p>Retry bookkeeping rides in the cloned message's application properties (header-tracked, so
 * it survives redelivery and pod restarts). Each retry is a new message, so its
 * {@code getDeliveryCount()} starts again at 0.
 *
 * <p>Every copy also carries the first copy's enqueue time, which bounds how long a message is retried at all
 * ({@link #attemptDeadline}), and expires at that bound.
 */
@Slf4j
@Service
public class ScheduledRetryService {

    /** Application-property keys carried between attempts. */
    public static final String PROP_RETRY_COUNT          = "RetryCount";
    public static final String PROP_RETRY_COUNT_PREFIX   = "RetryCount.";
    public static final String PROP_LAST_RETRY_REASON    = "LastRetryReason";
    public static final String PROP_LAST_RETRY_DETAIL    = "LastRetryReasonDetail";
    public static final String PROP_LAST_RETRY_AT        = "LastRetryAt";
    public static final String PROP_LAST_RETRY_AFTER_SEC = "LastRetryAfterSec";
    /** When the first copy of the message was enqueued; a copy's own enqueue time is when it was re-enqueued. */
    public static final String PROP_ORIGINAL_ENQUEUED_TIME = "OriginalEnqueuedTime";
    /** The first copy's queue sequence number; with {@link #PROP_ORIGINAL_ENQUEUED_TIME} it names the attempt. */
    public static final String PROP_ORIGINAL_SEQUENCE_NUMBER = "OriginalSequenceNumber";

    /** The least a re-enqueued copy may live, so it is still delivered before it expires. */
    static final Duration MIN_TIME_TO_LIVE = Duration.ofMinutes(1);
    static final String DEADLINE_PASSED = "ATTEMPT_DEADLINE_PASSED";

    private static final int MAX_DETAIL_LEN = 1024;

    private final MessageSender inboundSenderClient;
    private final RetryPolicy policy;
    private final MeterRegistry meterRegistry;
    private final Clock clock;

    public ScheduledRetryService(
            @Qualifier("inboundSender") MessageSender inboundSenderClient,
            AgentProperties properties,
            MeterRegistry meterRegistry,
            Clock clock) {
        this.inboundSenderClient = inboundSenderClient;
        this.policy = RetryPolicy.from(properties.getRetry());
        this.meterRegistry = meterRegistry;
        this.clock = clock;
    }

    /** The policy snapshot built at startup — shared with the listener's give-up decision. */
    public RetryPolicy policy() {
        return policy;
    }

    /** Reads {@code RetryCount} from the message's application properties (0 if absent/unparseable). */
    public static int currentRetryCount(InboundMessage message) {
        return parseInt(message.getApplicationProperties().get(PROP_RETRY_COUNT), 0);
    }

    /** Whether {@code message} may not be retried for {@code reason} again: its retries for it are used up. */
    public boolean retriesUsedUp(InboundMessage message, String reason) {
        return policy.exhausted(reason, currentRetryCount(message), currentRetryCount(message, reason));
    }

    /**
     * The last instant {@code message} may still be worked on: its original enqueue time plus the attempt-age bound
     * of its kind (renewal or new order). No retry is scheduled past it, and no copy outlives it.
     */
    public Instant attemptDeadline(InboundMessage message) {
        boolean renewal = "CERT_RENEWAL".equals(String.valueOf(message.getApplicationProperties().get("MessageType")));
        return originalEnqueuedTime(message).plus(policy.maxAttemptAgeFor(renewal));
    }

    /**
     * When a retry {@code delay} from now would run and how long its copy may live, from one reading of the clock;
     * empty when less than {@link #MIN_TIME_TO_LIVE} of {@code message}'s deadline would be left by then.
     */
    public Optional<RetrySlot> slotFor(InboundMessage message, Duration delay) {
        OffsetDateTime scheduledFor = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC).plus(delay);
        Duration timeToLive = Duration.between(scheduledFor.toInstant(), attemptDeadline(message));
        return timeToLive.compareTo(MIN_TIME_TO_LIVE) < 0
                ? Optional.empty()
                : Optional.of(new RetrySlot(delay, scheduledFor, timeToLive));
    }

    /**
     * Refuses to start work on a message whose deadline has passed, so a late first delivery orders nothing.
     *
     * @throws PermanentAgentException {@code ATTEMPT_DEADLINE_PASSED}
     */
    public void requireTimeLeft(InboundMessage message) {
        Instant deadline = attemptDeadline(message);
        if (clock.instant().isAfter(deadline)) {
            throw new PermanentAgentException(DEADLINE_PASSED,
                    "The message's attempt deadline " + deadline + " passed before work started");
        }
    }

    /** When a retry runs ({@code delay} after it was planned) and how long its copy may live. */
    public record RetrySlot(Duration delay, OffsetDateTime scheduledFor, Duration timeToLive) {
    }

    /**
     * Names the attempt {@code message} belongs to: its first copy's sequence number and enqueue time. A redelivery
     * and every retry copy carry the same key; a new command is a new message with its own. Empty for a message
     * without an enqueue time.
     */
    public static Optional<String> attemptKey(InboundMessage message) {
        if (message == null) {
            return Optional.empty();
        }
        Object stampedTime = message.getApplicationProperties().get(PROP_ORIGINAL_ENQUEUED_TIME);
        String enqueuedTime = stampedTime != null ? stampedTime.toString()
                : message.getEnqueuedTime() == null ? null : message.getEnqueuedTime().toInstant().toString();
        return enqueuedTime == null ? Optional.empty()
                : Optional.of(originalSequenceNumber(message) + "@" + enqueuedTime);
    }

    private static long originalSequenceNumber(InboundMessage message) {
        Object stamped = message.getApplicationProperties().get(PROP_ORIGINAL_SEQUENCE_NUMBER);
        if (stamped instanceof Number n) {
            return n.longValue();
        }
        if (stamped != null) {
            try {
                return Long.parseLong(stamped.toString().trim());
            } catch (NumberFormatException ignored) {
                // An unreadable stamp falls back to this copy's own sequence number.
            }
        }
        return message.getSequenceNumber();
    }

    private Instant originalEnqueuedTime(InboundMessage message) {
        Object stamped = message.getApplicationProperties().get(PROP_ORIGINAL_ENQUEUED_TIME);
        if (stamped != null) {
            try {
                return Instant.parse(stamped.toString());
            } catch (DateTimeParseException ignored) {
                // An unreadable stamp falls back to this copy's own enqueue time.
            }
        }
        return message.getEnqueuedTime() == null ? clock.instant() : message.getEnqueuedTime().toInstant();
    }

    /** Reads {@code RetryCount.<reason>}, the retries scheduled for {@code reason} alone (0 if absent). */
    public static int currentRetryCount(InboundMessage message, String reason) {
        return parseInt(message.getApplicationProperties().get(PROP_RETRY_COUNT_PREFIX + reason), 0);
    }

    /**
     * Clones the in-flight message onto the inbound queue for {@code slot},
     * incrementing {@code RetryCount} and stamping the retry reason, then completes the original.
     *
     * @return {@code true} if the retry was scheduled and the original completed; {@code false}
     *         (logged at WARN) if anything threw — the caller falls back to {@code abandon()}.
     */
    public boolean scheduleRetry(InboundContext ctx, RetrySlot slot,
                                 String reasonCode, String reasonMessage) {
        return scheduleRetry(ctx, slot, reasonCode, reasonMessage, null);
    }

    /** Variant that stamps an {@link com.certping.agent.exception.IssuanceCheckpoint}'s
     *  {@code Checkpoint.*} application properties onto the cloned message, so the next attempt
     *  can resume past the billable boundary instead of replaying it. */
    public boolean scheduleRetry(InboundContext ctx, RetrySlot slot,
                                 String reasonCode, String reasonMessage,
                                 IssuanceCheckpoint checkpoint) {
        try {
            InboundMessage original = ctx.getMessage();

            // Body is copied verbatim; messageId is re-assigned by the server on the new send.
            TransportMessage retry = new TransportMessage(original.getBody());

            // Copy all existing application properties (MessageType, etc.), then overwrite the
            // retry-tracking ones.
            Map<String, Object> props = retry.getApplicationProperties();
            props.putAll(original.getApplicationProperties());

            int nextRetryCount = currentRetryCount(original) + 1;
            props.put(PROP_RETRY_COUNT, nextRetryCount);
            props.put(PROP_RETRY_COUNT_PREFIX + reasonCode, currentRetryCount(original, reasonCode) + 1);
            props.put(PROP_LAST_RETRY_REASON, reasonCode);
            props.put(PROP_LAST_RETRY_DETAIL, truncate(reasonMessage, MAX_DETAIL_LEN));
            props.put(PROP_LAST_RETRY_AT, clock.instant().toString());
            props.put(PROP_LAST_RETRY_AFTER_SEC, slot.delay().toSeconds());
            props.put(PROP_ORIGINAL_ENQUEUED_TIME, originalEnqueuedTime(original).toString());
            props.put(PROP_ORIGINAL_SEQUENCE_NUMBER, originalSequenceNumber(original));

            if (checkpoint != null) {
                // Overwrite any prior Checkpoint.* with the latest snapshot (monotonic forward
                // progress — newer step never regresses). The map is small (<10 entries).
                checkpoint.toAppProperties().forEach(props::put);
            }

            // Preserve trace/dedupe identity across attempts.
            if (original.getCorrelationId() != null) {
                retry.setCorrelationId(original.getCorrelationId());
            }
            if (original.getSubject() != null) {
                retry.setSubject(original.getSubject());
            }

            retry.setScheduledEnqueueTime(slot.scheduledFor());
            // A scheduled message's time to live counts from its scheduled enqueue time.
            retry.setTimeToLive(slot.timeToLive());

            // Send the future-dated copy first, then settle the original. If complete() fails
            // after a successful send the lock will expire and redeliver, producing at most one
            // duplicate attempt — processors must be idempotent.
            inboundSenderClient.sendMessage(retry);
            ctx.complete();

            log.info("ScheduledRetry queue={} retryCount={} reason={} delaySec={} scheduledEnqueueTime={}",
                    safeEntityPath(), nextRetryCount, reasonCode, slot.delay().toSeconds(), slot.scheduledFor());
            String messageType = String.valueOf(original.getApplicationProperties().get("MessageType"));
            meterRegistry.counter("agent.message.retry.scheduled.count",
                    "messageType", messageType, "reasonCode", reasonCode).increment();
            meterRegistry.summary("agent.message.retry.delay.seconds",
                    "messageType", messageType).record(slot.delay().toSeconds());
            return true;
        } catch (Exception e) {
            log.warn("ScheduledRetry failed (reason={}) — caller will fall back to abandon: {}",
                    reasonCode, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Resolves the next delay:
     * <ul>
     *   <li>{@code retryAfter != null} — honor it, capped at {@code hardCap}.</li>
     *   <li>{@code retryAfter == null} — blind backoff step for {@code retryCount}.</li>
     * </ul>
     * Upward jitter (0..{@code jitterPercent}%) is then added. Jitter is one-directional so a
     * honored {@code Retry-After} is never shortened below what upstream asked for — shortening it
     * would risk re-hitting the same rate limit on the retry.
     */
    public static Duration pickDelay(Duration retryAfter, int retryCount, RetryPolicy p, Duration hardCap) {
        Duration base;
        if (retryAfter != null) {
            base = retryAfter.compareTo(hardCap) > 0 ? hardCap : retryAfter;
        } else {
            base = p.blindBackoffFor(retryCount);
        }
        return applyUpwardJitter(base, p.jitterPercent());
    }

    private static Duration applyUpwardJitter(Duration base, int jitterPercent) {
        long baseSec = Math.max(1L, base.toSeconds());
        if (jitterPercent <= 0) {
            return Duration.ofSeconds(baseSec);
        }
        long maxExtra = baseSec * jitterPercent / 100L;
        long extra = maxExtra <= 0 ? 0L : ThreadLocalRandom.current().nextLong(maxExtra + 1);
        return Duration.ofSeconds(baseSec + extra);
    }

    private String safeEntityPath() {
        try {
            return inboundSenderClient.getEntityPath();
        } catch (RuntimeException e) {
            return "<unknown>";
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max);
    }

    private static int parseInt(Object value, int fallback) {
        if (value instanceof Number n) {
            return n.intValue();
        }
        if (value instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }
}
