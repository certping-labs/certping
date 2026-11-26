// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.DeadLetterOptions;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.interceptor.RequestContextInterceptor;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.utils.MessageIds;
import com.certping.notification.util.OtelSpanContext;
import com.certping.notification.utils.RequestContextLogger;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.CannotCreateTransactionException;
import tools.jackson.databind.cfg.EnumFeature;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationMessageHandler {

    private final NotificationService notificationService;
    private final ScheduledRetryService scheduledRetryService;
    private final UndeliveredEmailService undeliveredEmailService;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults()
            // Forward-compat: an unknown notificationType/notificationAction emitted by a newer
            // publisher deserialises to null instead of throwing and dead-lettering the whole batch.
            // Null-action events are dropped in processMessageWithTypes rather than NPE-ing downstream.
            .configure(EnumFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL, true)
            // Publishers may add fields the notifier does not read yet; never fail on them.
            .disable(tools.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();
    @Qualifier("notificationTaskExecutor")
    private final TaskExecutor taskExecutor;
    private final MeterRegistry meterRegistry;
    private final DeliveryTimeouts deliveryTimeouts;

    /**
     * Counts events dropped because this notifier has no action, and so no template, for them. It has
     * no tags, so a publisher cannot grow its series; the INFO log names each action.
     */
    static final String UNKNOWN_ACTION_METRIC = "notifier.events.unknown_action";

    /** Counts failed deliver-once attempts; the database-backed open gauge carries paging state. */
    static final String UNDELIVERED_METRIC = "notification.deliver_once.undelivered";
    /** A deliver-once email given up on after its maximum age; it is then dead-lettered. */
    static final String EXPIRED_METRIC = "notification.deliver_once.expired";
    /** A deliver-once email delivered by an hourly retry after it was counted undelivered. */
    static final String RECOVERED_METRIC = "notification.deliver_once.recovered";
    static final String DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE";

    /**
     * A database outage or failover outlasts the broker's three immediate redeliveries; the
     * scheduled retry spaces the attempts out instead of dead-lettering within seconds.
     */
    private static final Duration DATABASE_RETRY_AFTER = Duration.ofMinutes(1);

    private static final Set<String> KNOWN_ACTIONS =
            Arrays.stream(NotificationAction.values()).map(Enum::name).collect(Collectors.toUnmodifiableSet());

    /** An action name as a publisher writes one; anything else is logged as "invalid". */
    private static final Pattern ACTION_NAME = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");

    private static final int MAX_DELIVERY_COUNT = 3;

    public void processSystemEvent(InboundContext context) {
        handle(context, List.of(NotificationType.SYSTEM_EVENT), List.of("system"));
    }

    public void processAccountEvent(InboundContext context) {
        handle(context, List.of(NotificationType.ACCOUNT_EVENT), List.of("account"));
    }

    /**
     * Handles one message under the ids of the request it was published for, then writes the
     * message's canonical line: how it was settled, how many events and recipients it had, and how
     * long it took. The line names no recipient.
     */
    private void handle(InboundContext context, List<NotificationType> expectedTypes,
                        List<String> labels) {
        long began = System.nanoTime();
        MessageIds ids = setupRequestContext(context);
        try {
            Handled handled = processMessageWithTypes(context, ids, expectedTypes, labels);
            contextLogger().info(
                    "notification message handled outcome={} type={} notificationKey={} events={} recipients={} durationMs={}",
                    handled.outcome(), String.join(",", labels), handled.keys(), handled.events(), handled.recipients(),
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began));
        } finally {
            RequestContextInterceptor.clearContext();
        }
    }

    /**
     * How a message was settled, for its canonical line: keys are its events' idempotency keys in
     * their loggable form, "none" for a message whose events were never read.
     */
    private record Handled(String outcome, String keys, int events, int recipients) {

        static Handled of(String outcome) {
            return new Handled(outcome, "none", 0, 0);
        }

        static Handled of(String outcome, List<NotificationEvent> events) {
            if (events.isEmpty()) {
                return of(outcome);
            }
            int recipients = events.stream()
                    .mapToInt(event -> event.getRecipients() == null ? 0 : event.getRecipients().size()).sum();
            String keys = events.stream().map(event -> String.valueOf(MessageIds.loggable(event.idempotencyKey())))
                    .collect(Collectors.joining(","));
            return new Handled(outcome, keys, events.size(), recipients);
        }
    }

    /**
     * Puts the ids the message's application properties carry in the logging context, with the
     * broker's message id as the idempotency key until the body names the notification's own.
     */
    private MessageIds setupRequestContext(InboundContext context) {
        InboundMessage message = context.getMessage();
        MessageIds ids = MessageIds.from(message.getApplicationProperties());
        String messageId = message.getMessageId();
        RequestContextInterceptor.setCurrentIdempotencyKey(MessageIds.loggable(messageId));
        if (ids.requestId() != null) {
            RequestContextInterceptor.setCurrentRequestId(ids.requestId());
        }
        if (ids.correlationId() != null) {
            RequestContextInterceptor.setCurrentCorrelationId(ids.correlationId());
        }
        OtelSpanContext.enrichInboundBatch(ids.requestId(),
                firstValid(ids.correlationId(), message.getCorrelationId()), messageId);
        return ids;
    }

    /**
     * For a publisher that sends no ids in the application properties: the first event's own
     * {@code requestId} and {@code correlationId} become the message's.
     */
    private void populateMdcFromBody(List<NotificationEvent> events, MessageIds ids) {
        if (events == null || events.isEmpty()) {
            return;
        }
        NotificationEvent head = events.get(0);
        String requestId = firstValid(ids.requestId(), head.getRequestId());
        if (requestId != null) {
            RequestContextInterceptor.setCurrentRequestId(requestId);
        }
        String correlationId = firstValid(ids.correlationId(), head.getCorrelationId());
        if (correlationId != null) {
            RequestContextInterceptor.setCurrentCorrelationId(correlationId);
        }
    }

    /** The first candidate that is a valid id, or null. */
    private static String firstValid(String... candidates) {
        for (String candidate : candidates) {
            String valid = MessageIds.valid(candidate);
            if (valid != null) {
                return valid;
            }
        }
        return null;
    }

    /** The action names in the batch this notifier has no enum value, and so no template, for. */
    private List<String> unknownActions(String json) {
        List<String> unknown = new ArrayList<>();
        try {
            for (JsonNode event : objectMapper.readTree(json)) {
                String action = event.path("notificationAction").asString("");
                if (!KNOWN_ACTIONS.contains(action)) {
                    unknown.add(ACTION_NAME.matcher(action).matches() ? action : "invalid");
                }
            }
        } catch (Exception e) {
            unknown.add("invalid");
        }
        return unknown;
    }

    private Handled processMessageWithTypes(InboundContext context, MessageIds ids,
                                            List<NotificationType> expectedTypes, List<String> labels) {
        String labelStr = String.join(" or ", labels);
        InboundMessage message = context.getMessage();
        int deliveryCount = (int) message.getDeliveryCount();
        
        // Check if message has exceeded max delivery attempts
        if (deliveryCount >= MAX_DELIVERY_COUNT) {
            recordUndeliveredBody(message);
            contextLogger().error("Message exceeded maximum delivery count ({}). Moving to DLQ. MessageId: {}",
                    MAX_DELIVERY_COUNT, MessageIds.loggable(message.getMessageId()));
            DeadLetterOptions options = new DeadLetterOptions()
                    .setDeadLetterReason("MaxDeliveryCountExceeded")
                    .setDeadLetterErrorDescription(
                            String.format("Message failed processing after %d attempts", deliveryCount));
            context.deadLetter(options);
            return Handled.of("dead_lettered", readableEvents(message));
        }
        try {
            String json = context.getMessage().getBody().toString();
            List<NotificationEvent> events = readEvents(json);

            populateMdcFromBody(events, ids);

            long unknownActionCount = events.stream()
                    .filter(event -> event.getNotificationAction() == null)
                    .count();
            if (unknownActionCount > 0) {
                for (String action : unknownActions(json)) {
                    contextLogger().info("No template for notificationAction {}: this notifier does not know it yet", action);
                    meterRegistry.counter(UNKNOWN_ACTION_METRIC).increment();
                }
                contextLogger().warn("Dropping {} event(s) with unknown/unmapped notificationAction (forward-compat)",
                        unknownActionCount);
            }

            // Filter events of expected types (drop unknown-action events deserialised to null)
            List<NotificationEvent> filteredEvents = events.stream()
                    .filter(event -> event.getNotificationAction() != null)
                    .filter(event -> expectedTypes.contains(event.getNotificationType()))
                    .collect(Collectors.toList());

            if (filteredEvents.isEmpty()) {
                contextLogger().info("No {} events to process", labelStr);
                context.complete();
                return Handled.of("completed");
            }

            // Process events in parallel using CompletableFuture, tracking
            // each event's outcome individually so we can retry ONLY the
            // failed subset. Otherwise, if any event failed, rescheduling the
            // whole batch body would cause already-DELIVERED events to be
            // re-sent, generating duplicate emails.
            //
            // NotificationService.processNotification is find-or-insert by
            // event.requestId — one row per logical notification, updated in
            // place across retries. The retry preservation is automatic since
            // the retry copies the body verbatim; no listener-side plumbing
            // needed.
            // The workers do not inherit the receiver thread's context, so each event sets its own.
            final String messageRequestId = RequestContextInterceptor.getCurrentRequestId();
            final String messageCorrelationId = RequestContextInterceptor.getCurrentCorrelationId();
            final String messageKey = RequestContextInterceptor.getCurrentIdempotencyKey();

            List<CompletableFuture<EventOutcome>> futures = filteredEvents.stream()
                    .map(event -> CompletableFuture.supplyAsync(() -> {
                        RequestContextInterceptor.setCurrentRequestId(
                                firstValid(ids.requestId(), event.getRequestId(), messageRequestId));
                        RequestContextInterceptor.setCurrentCorrelationId(
                                firstValid(ids.correlationId(), event.getCorrelationId(), messageCorrelationId));
                        RequestContextInterceptor.setCurrentNotificationKey(
                                event.idempotencyKey() != null ? event.idempotencyKey() : messageKey);
                        try {
                            notificationService.processNotification(event);
                            contextLogger().info("Successfully processed {} event {}",
                                    event.getNotificationType().toString().toLowerCase(), event.getNotificationAction());
                            return new EventOutcome(event, null);
                        } catch (Exception e) {
                            if (unwrapRetryable(e) != null) {
                                contextLogger().warn("Retryable {} event ({}): {} — will reschedule",
                                        event.getNotificationType().toString().toLowerCase(),
                                        unwrapRetryable(e).getReasonCode(),
                                        unwrapRetryable(e).getMessage());
                            } else {
                                contextLogger().error("Error processing {} event: {}",
                                        event.getNotificationType().toString().toLowerCase(), e.getMessage(), e);
                            }
                            return new EventOutcome(event, e);
                        } finally {
                            // Always clear — the worker thread returns to the
                            // pool and shouldn't leak MDC state onto the next
                            // event it picks up.
                            RequestContextInterceptor.clearContext();
                        }
                    }, taskExecutor))
                    .collect(Collectors.toList());

            List<EventOutcome> outcomes;
            try {
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                        .get(deliveryTimeouts.eventDeadline().multipliedBy(filteredEvents.size()).toMillis(),
                                TimeUnit.MILLISECONDS);
                outcomes = futures.stream()
                        .map(CompletableFuture::join)
                        .collect(Collectors.toList());
            } catch (TimeoutException timeout) {
                contextLogger().warn("{} {} event(s) outlasted their deadline; the message is redelivered",
                        filteredEvents.size(), labelStr);
                context.abandon();
                return Handled.of("abandoned", filteredEvents);
            } catch (Exception e) {
                contextLogger().error("Batch-wide processing failed for {} events: {}",
                        labelStr, e.getMessage(), e);
                if (deliveryCount >= MAX_DELIVERY_COUNT - 1) {
                    recordUndelivered(filteredEvents, UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, message);
                    DeadLetterOptions options = new DeadLetterOptions()
                            .setDeadLetterReason(e.getClass().getSimpleName())
                            .setDeadLetterErrorDescription(
                                    String.format("Failed to process after %d attempts. Error: %s",
                                            deliveryCount + 1, e.getMessage()));
                    context.deadLetter(options);
                    return Handled.of("dead_lettered", filteredEvents);
                }
                context.abandon();
                return Handled.of("abandoned", filteredEvents);
            }

            List<EventOutcome> failures = outcomes.stream()
                    .filter(o -> o.failure != null)
                    .collect(Collectors.toList());

            countRecovered(outcomes);
            if (failures.isEmpty()) {
                context.complete();
                contextLogger().info("Successfully processed all {} events in batch", labelStr);
                return Handled.of("completed", filteredEvents);
            }

            List<EventOutcome> retryable = failures.stream()
                    .filter(o -> unwrapRetryable(o.failure) != null)
                    .collect(Collectors.toList());
            List<EventOutcome> permanent = failures.stream()
                    .filter(o -> unwrapRetryable(o.failure) == null)
                    .collect(Collectors.toList());
            recordUndelivered(permanent.stream().map(o -> o.event).toList(),
                    UndeliveredEmailService.Outcome.PERMANENT_FAILURE, message);
            if (retryable.isEmpty() && permanent.stream().allMatch(o -> o.failure instanceof RecipientsRefusedException)) {
                context.complete();
                contextLogger().warn("{} event(s) refused for good by every recipient left; recorded and completed",
                        permanent.size());
                return Handled.of("completed", filteredEvents);
            }

            List<EventOutcome> deliverOnce = retryable.stream()
                    .filter(this::hasRetryableRecipients).toList();
            if (!deliverOnce.isEmpty()) {
                List<EventOutcome> others = retryable.stream().filter(o -> !deliverOnce.contains(o)).toList();
                if (rescheduleUntilDelivered(context, deliverOnce, others, filteredEvents.size(), permanent.size())) {
                    return Handled.of("rescheduled", filteredEvents);
                }
            } else if (!retryable.isEmpty()) {
                List<NotificationEvent> retryEvents = retryable.stream()
                        .map(o -> o.event)
                        .collect(Collectors.toList());
                Duration maxRetryAfter = retryable.stream()
                        .map(o -> unwrapRetryable(o.failure).getRetryAfter())
                        .max(Comparator.naturalOrder())
                        .orElse(Duration.ofSeconds(60));
                RetryableNotificationException first = unwrapRetryable(retryable.get(0).failure);
                String reason = String.format("%d/%d events retryable (%d permanent)",
                        retryable.size(), filteredEvents.size(), permanent.size());
                String newBodyJson;
                try {
                    newBodyJson = retryBody(retryEvents);
                } catch (Exception jsonError) {
                    contextLogger().error("Failed to serialise retry subset — falling back to abandon: {}",
                            jsonError.getMessage(), jsonError);
                    context.abandon();
                    return Handled.of("abandoned", filteredEvents);
                }
                if (scheduledRetryService.scheduleRetry(context, maxRetryAfter,
                        first.getReasonCode(), reason, newBodyJson)) {
                    contextLogger().info(
                            "Rescheduled {}/{} events for {}s (reason={}, retryCount={}, {} permanent-failed)",
                            retryable.size(), filteredEvents.size(),
                            maxRetryAfter.toSeconds(), first.getReasonCode(),
                            scheduledRetryService.currentRetryCount(message) + 1,
                            permanent.size());
                    return Handled.of("rescheduled", filteredEvents);
                }
                // Reschedule failed OR budget exhausted — fall through to the
                // abandon/deadLetter path so ops sees a DLQ entry rather than
                // a silent drop.
            }

            recordUndelivered(retryable.stream().filter(this::hasRetryableRecipients)
                    .map(o -> o.event).toList(), UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, message);

            contextLogger().error(
                    "Batch had {} permanent failure(s) (Attempt {}/{}): first error: {}",
                    permanent.size(), deliveryCount + 1, MAX_DELIVERY_COUNT,
                    permanent.isEmpty() ? "(reschedule refused)" : permanent.get(0).failure.getMessage());
            if (deliveryCount >= MAX_DELIVERY_COUNT - 1) {
                Throwable representative = permanent.isEmpty()
                        ? failures.get(0).failure
                        : permanent.get(0).failure;
                DeadLetterOptions options = new DeadLetterOptions()
                        .setDeadLetterReason(representative.getClass().getSimpleName())
                        .setDeadLetterErrorDescription(
                                String.format("Failed to process after %d attempts. Error: %s",
                                        deliveryCount + 1, representative.getMessage()));
                context.deadLetter(options);
                return Handled.of("dead_lettered", filteredEvents);
            }
            context.abandon();
            return Handled.of("abandoned", filteredEvents);
        } catch (Exception e) {
            // Deserialization failures are deterministic — the same broken payload
            // will fail again with a fresh delivery attempt, so retrying is pure
            // waste (each cycle costs a poll and log volume). Dead-letter
            // immediately so ops sees the poison message right away instead of
            // ~3× the noise.
            contextLogger().error("DLQ-ing {} message: deserialization failed, MessageId: {} — {}",
                    labelStr, MessageIds.loggable(message.getMessageId()), e.getMessage(), e);
            DeadLetterOptions options = new DeadLetterOptions()
                    .setDeadLetterReason("DeserializationError")
                    .setDeadLetterErrorDescription(
                            String.format("Failed to deserialize message: %s", e.getMessage()));
            context.deadLetter(options);
            return Handled.of("dead_lettered");
        }
    }

    /**
     * Retries the deliver-once events until every recipient has the email, the other retryable events
     * within the standard budget, each as a copy of its own. A deliver-once email that outlives the
     * budget is retried hourly and recorded as open; one older than its maximum age is counted
     * expired and left to the dead-letter path. Returns true when the deliver-once copy was sent
     * and the original completed, even if a standard copy was refused.
     */
    private boolean rescheduleUntilDelivered(InboundContext context, List<EventOutcome> deliverOnce,
                                             List<EventOutcome> others, int batchSize, int permanentCount) {
        List<ScheduledRetryService.RetryCopy> copies = new ArrayList<>();
        try {
            copies.add(retryCopy(deliverOnce, batchSize, permanentCount, ScheduledRetryService.Policy.UNTIL_DELIVERED));
            if (!others.isEmpty()) {
                copies.add(0, retryCopy(others, batchSize, permanentCount, ScheduledRetryService.Policy.STANDARD));
            }
        } catch (Exception jsonError) {
            contextLogger().error("Failed to serialise retry subset — falling back to abandon: {}",
                    jsonError.getMessage(), jsonError);
            return false;
        }
        List<ScheduledRetryService.Scheduled> outcomes = scheduledRetryService.scheduleRetries(context, copies);
        int nextRetryCount = scheduledRetryService.currentRetryCount(context.getMessage()) + 1;
        ScheduledRetryService.Scheduled deliverOutcome = outcomes.get(outcomes.size() - 1);
        boolean copySent = !outcomes.contains(ScheduledRetryService.Scheduled.FAILED)
                && outcomes.stream().anyMatch(outcome -> outcome == ScheduledRetryService.Scheduled.WITHIN_BUDGET
                        || outcome == ScheduledRetryService.Scheduled.PAST_BUDGET);
        switch (deliverOutcome) {
            case PAST_BUDGET -> {
                if (nextRetryCount == scheduledRetryService.getMaxScheduledRetries() + 1) {
                    recordUndelivered(deliverOnce.stream().map(o -> o.event).toList(),
                            UndeliveredEmailService.Outcome.PENDING_RETRY, context.getMessage());
                    contextLogger().error("Deliver-once email(s) {} still undelivered after {} retries; retrying hourly",
                            requestIds(deliverOnce), scheduledRetryService.getMaxScheduledRetries());
                }
            }
            case REFUSED -> {
                count(EXPIRED_METRIC, deliverOnce);
                if (copySent) {
                    recordUndelivered(deliverOnce.stream().map(o -> o.event).toList(),
                            UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, context.getMessage());
                }
                contextLogger().error("Deliver-once email(s) {} never reached every recipient and are given up on",
                        requestIds(deliverOnce));
            }
            case WITHIN_BUDGET, FAILED -> {
            }
        }
        if (outcomes.contains(ScheduledRetryService.Scheduled.REFUSED) && deliverOutcome != ScheduledRetryService.Scheduled.REFUSED) {
            contextLogger().error("Standard email retry was refused while deliver-once copy was scheduled: {}",
                    requestIds(others));
        }
        return copySent;
    }

    private ScheduledRetryService.RetryCopy retryCopy(List<EventOutcome> subset, int batchSize, int permanentCount,
                                                      ScheduledRetryService.Policy policy) throws Exception {
        Duration retryAfter = subset.stream()
                .map(o -> unwrapRetryable(o.failure).getRetryAfter())
                .max(Comparator.naturalOrder())
                .orElse(Duration.ofSeconds(60));
        RetryableNotificationException first = unwrapRetryable(subset.get(0).failure);
        String reason = String.format("%d/%d events retryable (%d permanent)", subset.size(), batchSize, permanentCount);
        String body = retryBody(subset.stream().map(o -> o.event).toList());
        return new ScheduledRetryService.RetryCopy(retryAfter, first.getReasonCode(), reason, body, policy);
    }

    private String retryBody(List<NotificationEvent> events) throws Exception {
        return objectMapper.writeValueAsString(events.stream().map(event -> {
            NotificationEvent copy = event.toBuilder().build();
            if ((copy.getRoles() != null && !copy.getRoles().isEmpty()) || copy.isIncludeUser()) {
                copy.setRecipients(null);
            }
            return copy;
        }).toList());
    }

    private void countRecovered(List<EventOutcome> outcomes) {
        for (EventOutcome outcome : outcomes) {
            if (outcome.failure == null && outcome.event.isDeliverOnce()) {
                try {
                    if (undeliveredEmailService.resolve(outcome.event)) {
                        count(RECOVERED_METRIC, List.of(outcome));
                        contextLogger().info("Deliver-once email {} recovered", MessageIds.loggable(outcome.event.idempotencyKey()));
                    }
                } catch (Exception failure) {
                    contextLogger().error("Could not close undelivered record for request {}",
                            MessageIds.loggable(outcome.event.idempotencyKey()), failure);
                }
            }
        }
    }

    private void count(String metric, List<EventOutcome> events) {
        for (EventOutcome o : events) {
            meterRegistry.counter(metric, "action", o.event.getNotificationAction().name()).increment();
        }
    }

    /**
     * The events of a message body, with DeliverOncePolicy applied: the one place it runs, so every
     * path that settles them (processing, retry copies, dead-lettering, undelivered records) sees the
     * same deliver-once flag and key.
     */
    private List<NotificationEvent> readEvents(String json) {
        List<NotificationEvent> events = objectMapper.readValue(json, new TypeReference<List<NotificationEvent>>() {});
        if (events != null) {
            events.forEach(DeliverOncePolicy::apply);
        }
        return events;
    }

    /** The events of a message that is settled without being processed; none when its body cannot be read. */
    private List<NotificationEvent> readableEvents(InboundMessage message) {
        try {
            return readEvents(message.getBody().toString()).stream().filter(Objects::nonNull).toList();
        } catch (Exception unreadable) {
            return List.of();
        }
    }

    private void recordUndeliveredBody(InboundMessage message) {
        try {
            if (!hasNoRecipientReason(message)) {
                recordUndelivered(readEvents(message.getBody().toString()),
                        UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, message);
            }
        } catch (Exception failure) {
            contextLogger().error("Could not inspect dead-lettered email batch for undelivered requests", failure);
        }
    }

    private boolean hasRetryableRecipients(EventOutcome outcome) {
        return outcome.event.isDeliverOnce()
                && !NotificationService.NO_RECIPIENT.equals(unwrapRetryable(outcome.failure).getReasonCode());
    }

    private static boolean hasNoRecipientReason(InboundMessage message) {
        return message.getApplicationProperties() != null && NotificationService.NO_RECIPIENT.equals(
                message.getApplicationProperties().get(ScheduledRetryService.PROP_LAST_RETRY_REASON));
    }

    private void recordUndelivered(List<NotificationEvent> events, UndeliveredEmailService.Outcome outcome,
                                   InboundMessage message) {
        if (outcome != UndeliveredEmailService.Outcome.PERMANENT_FAILURE && hasNoRecipientReason(message)) {
            return;
        }
        for (NotificationEvent event : events) {
            if (event != null && event.isDeliverOnce()) {
                if (undeliveredEmailService.record(event, outcome, message)) {
                    meterRegistry.counter(UNDELIVERED_METRIC, "action",
                            event.getNotificationAction() == null ? "unknown" : event.getNotificationAction().name()).increment();
                }
            }
        }
    }

    private static List<String> requestIds(List<EventOutcome> events) {
        return events.stream().map(o -> String.valueOf(MessageIds.loggable(o.event.idempotencyKey()))).toList();
    }

    private static final class EventOutcome {
        final NotificationEvent event;
        final Throwable failure;

        EventOutcome(NotificationEvent event, Throwable failure) {
            this.event = event;
            this.failure = failure;
        }
    }

    /**
     * Walk the (possibly wrapped) exception chain looking for a
     * {@link RetryableNotificationException}, or a database that is unreachable or timed out,
     * which is retried as {@link #DATABASE_UNAVAILABLE}. Handles both direct throws and
     * exceptions bubbled up through {@code CompletableFuture} /
     * {@code RuntimeException} wrapping.
     */
    private RetryableNotificationException unwrapRetryable(Throwable t) {
        Throwable current = t;
        while (current != null) {
            if (current instanceof RetryableNotificationException retryable) {
                return retryable;
            }
            if (current instanceof CannotCreateTransactionException
                    || current instanceof DataAccessResourceFailureException
                    || current instanceof TransientDataAccessException) {
                return new RetryableNotificationException(DATABASE_UNAVAILABLE, current.getMessage(),
                        DATABASE_RETRY_AFTER, current);
            }
            if (current.getCause() == current) {
                return null;
            }
            current = current.getCause();
        }
        return null;
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(NotificationMessageHandler.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
