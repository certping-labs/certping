// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.TransportMessage;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.MessageSender;
import com.certping.notification.transport.DeadLetterOptions;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.model.NotificationEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.transaction.CannotCreateTransactionException;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link NotificationMessageHandler} covering the paths that don't
 * require a full queue receiver plumbing — max-delivery DLQ, non-JSON body DLQ,
 * empty-filter complete, and the setupRequestContext MDC seeding.
 *
 * <p>End-to-end batch processing (worker threads + retryable classification)
 * is exercised via integration tests; unit-level coverage here focuses on the
 * message-level guards that fire before workers are dispatched.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NotificationMessageHandlerTest {

    @Mock private NotificationService notificationService;
    @Mock private ScheduledRetryService scheduledRetryService;
    @Mock private UndeliveredEmailService undeliveredEmailService;
    @Mock private InboundContext context;
    @Mock private InboundMessage message;
    @Mock private DeliveryTimeouts deliveryTimeouts;

    private NotificationMessageHandler listener;
    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

    @BeforeEach
    void setUp() {
        // Use a synchronous TaskExecutor so any accidentally-async work still executes
        // deterministically before the test assertions run.
        listener = new NotificationMessageHandler(notificationService, scheduledRetryService, undeliveredEmailService,
                new SyncTaskExecutor(),
                meterRegistry, deliveryTimeouts);
        when(deliveryTimeouts.eventDeadline()).thenReturn(Duration.ofMinutes(5));
        when(context.getMessage()).thenReturn(message);
        when(message.getMessageId()).thenReturn("msg-abc123");
        when(undeliveredEmailService.record(any(NotificationEvent.class),
                any(UndeliveredEmailService.Outcome.class), any())).thenReturn(true);
    }

    @Test
    void processSystemEvent_deliveryCountAtMax_deadLetters() {
        when(message.getDeliveryCount()).thenReturn(3L); // == MAX_DELIVERY_COUNT

        listener.processSystemEvent(context);

        ArgumentCaptor<DeadLetterOptions> dlq = ArgumentCaptor.forClass(DeadLetterOptions.class);
        verify(context).deadLetter(dlq.capture());
        assertThat(dlq.getValue().getDeadLetterReason()).isEqualTo("MaxDeliveryCountExceeded");
        verify(context, never()).complete();
    }

    @Test
    void processSystemEvent_deliveryCountAboveMax_deadLetters() {
        when(message.getDeliveryCount()).thenReturn(5L);

        listener.processSystemEvent(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void processAccountEvent_deliveryCountAtMax_deadLetters() {
        when(message.getDeliveryCount()).thenReturn(3L);

        listener.processAccountEvent(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void processSystemEvent_emptyEventList_completesWithoutProcessing() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getBody()).thenReturn(MessageBody.fromString("[]"));

        listener.processSystemEvent(context);

        verify(context).complete();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        verify(notificationService, never())
                .processNotification(any(com.certping.notification.model.NotificationEvent.class));
    }

    @Test
    void processAccountEvent_emptyEventList_completesWithoutProcessing() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getBody()).thenReturn(MessageBody.fromString("[]"));

        listener.processAccountEvent(context);

        verify(context).complete();
    }

    @Test
    void processSystemEvent_eventsAllOfWrongType_completes() {
        // Body deserialises but all events are ACCOUNT_EVENT, not SYSTEM_EVENT — filter drops them all.
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\"}]"));

        listener.processSystemEvent(context);

        verify(context).complete();
        verify(notificationService, never())
                .processNotification(any(com.certping.notification.model.NotificationEvent.class));
    }

    @Test
    void processSystemEvent_malformedJson_deadLetters() {
        // Deserialisation failure → immediate DLQ (not 3× retry). The class catches at the top
        // and dead-letters; this test asserts the DLQ path fires.
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getBody()).thenReturn(MessageBody.fromString("not-valid-json"));

        listener.processSystemEvent(context);

        // Either DLQ or exception rethrown — verify we did not silently complete.
        verify(context, never()).complete();
    }

    @Test
    void processSystemEvent_unknownActionField_dropsEventAndCompletes() {
        // notificationAction "SOMETHING_NEW" is unknown to the enum. With
        // READ_UNKNOWN_ENUM_VALUES_AS_NULL, the action deserialises to null and the filter drops it.
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"SYSTEM_EVENT\",\"notificationAction\":\"COMPLETELY_UNKNOWN_ACTION\"}]"));

        listener.processSystemEvent(context);

        verify(context).complete();
        verify(notificationService, never())
                .processNotification(any(com.certping.notification.model.NotificationEvent.class));
        assertThat(meterRegistry.counter(NotificationMessageHandler.UNKNOWN_ACTION_METRIC).count()).isEqualTo(1.0);
    }

    @Test
    void processSystemEvent_unknownActionsShareOneSeries() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"SYSTEM_EVENT\",\"notificationAction\":\"<bad action>\"},"
                        + "{\"notificationType\":\"SYSTEM_EVENT\",\"notificationAction\":\"NEW_ACTION_1\"},"
                        + "{\"notificationType\":\"SYSTEM_EVENT\",\"notificationAction\":\"NEW_ACTION_2\"}]"));

        listener.processSystemEvent(context);

        verify(context).complete();
        assertThat(meterRegistry.find(NotificationMessageHandler.UNKNOWN_ACTION_METRIC).counters()).hasSize(1);
        assertThat(meterRegistry.counter(NotificationMessageHandler.UNKNOWN_ACTION_METRIC).count()).isEqualTo(3.0);
    }

    // ── worker-lane paths: single event success / permanent failure / retryable ──

    @Test
    void processAccountEvent_singleEventSucceeds_completesContext() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\"," +
                "\"integrationType\":\"EMAIL\",\"email\":\"a@example.com\",\"requestId\":\"r-1\"}]"));

        listener.processAccountEvent(context);

        // NotificationService called + context completed
        verify(notificationService).processNotification(any(com.certping.notification.model.NotificationEvent.class));
        verify(context).complete();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void processAccountEvent_permanentFailure_notMaxAttempts_abandons() {
        when(message.getDeliveryCount()).thenReturn(0L); // < MAX_DELIVERY_COUNT - 1 = 2
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\"," +
                "\"integrationType\":\"EMAIL\",\"email\":\"a@example.com\",\"requestId\":\"r-1\"}]"));
        org.mockito.Mockito.doThrow(new RuntimeException("permanent boom"))
                .when(notificationService).processNotification(
                        any(com.certping.notification.model.NotificationEvent.class));

        listener.processAccountEvent(context);

        // Permanent failure + still under delivery budget → abandon (redeliver at broker),
        // not dead-letter.
        verify(context).abandon();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        verify(context, never()).complete();
    }

    @Test
    void processAccountEvent_permanentFailure_atLastAttempt_deadLetters() {
        when(message.getDeliveryCount()).thenReturn(2L); // MAX_DELIVERY_COUNT - 1
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\"," +
                "\"integrationType\":\"EMAIL\",\"email\":\"a@example.com\",\"requestId\":\"r-1\"}]"));
        org.mockito.Mockito.doThrow(new IllegalStateException("permanent boom"))
                .when(notificationService).processNotification(
                        any(com.certping.notification.model.NotificationEvent.class));

        listener.processAccountEvent(context);

        // Last delivery attempt → dead-letter with reason from the exception class.
        ArgumentCaptor<DeadLetterOptions> dlq = ArgumentCaptor.forClass(DeadLetterOptions.class);
        verify(context).deadLetter(dlq.capture());
        assertThat(dlq.getValue().getDeadLetterReason()).isEqualTo("IllegalStateException");
        assertThat(dlq.getValue().getDeadLetterErrorDescription())
                .contains("permanent boom")
                .contains("attempts");
    }

    @Test
    void processAccountEvent_retryableFailure_schedulesRetry() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getApplicationProperties()).thenReturn(java.util.Map.of());
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\"," +
                "\"integrationType\":\"EMAIL\",\"email\":\"a@example.com\",\"requestId\":\"r-1\"}]"));

        com.certping.notification.exception.RetryableNotificationException retryable =
                new com.certping.notification.exception.RetryableNotificationException(
                        "ACS_RATE_LIMITED", "3703s", java.time.Duration.ofSeconds(3703), null);
        org.mockito.Mockito.doThrow(retryable)
                .when(notificationService).processNotification(
                        any(com.certping.notification.model.NotificationEvent.class));
        when(scheduledRetryService.scheduleRetry(any(), any(), org.mockito.ArgumentMatchers.eq("ACS_RATE_LIMITED"),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(true);

        listener.processAccountEvent(context);

        // Retryable → delegate to ScheduledRetryService, no complete/abandon/dlq from listener.
        verify(scheduledRetryService).scheduleRetry(any(), any(),
                org.mockito.ArgumentMatchers.eq("ACS_RATE_LIMITED"),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
        verify(context, never()).complete();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void processSystemEvent_platformAlertWithNoRecipient_isRescheduledNotCompleted() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getApplicationProperties()).thenReturn(Map.of());
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"SYSTEM_EVENT\",\"notificationAction\":\"SYSTEM_DLQ_ALERT\"," +
                "\"integrationType\":\"EMAIL\",\"roles\":[\"SUPER_ADMIN\"],\"requestId\":\"health-1\"}]"));
        Duration retryAfter = Duration.ofMinutes(30);
        doThrow(new RetryableNotificationException(
                        NotificationService.NO_RECIPIENT, "nobody", retryAfter))
                .when(notificationService).processNotification(
                        any(NotificationEvent.class));
        when(scheduledRetryService.scheduleRetry(any(), any(), anyString(),
                anyString(), anyString()))
                .thenReturn(true);

        listener.processSystemEvent(context);

        verify(scheduledRetryService).scheduleRetry(any(), eq(retryAfter),
                eq(NotificationService.NO_RECIPIENT),
                anyString(),
                contains("health-1"));
        verify(context, never()).complete();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void processSystemEvent_databaseUnavailable_isRescheduledNotAbandoned() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getApplicationProperties()).thenReturn(Map.of());
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"SYSTEM_EVENT\",\"notificationAction\":\"SYSTEM_DLQ_ALERT\"," +
                "\"integrationType\":\"EMAIL\",\"roles\":[\"SUPER_ADMIN\"],\"requestId\":\"health-1\"}]"));
        when(scheduledRetryService.scheduleRetry(any(), any(), anyString(),
                anyString(), anyString()))
                .thenReturn(true);

        for (RuntimeException outage : List.<RuntimeException>of(
                new CannotCreateTransactionException("no connection"),
                new DataAccessResourceFailureException("connection reset"),
                new QueryTimeoutException("statement timeout"))) {
            clearInvocations(scheduledRetryService, context);
            doThrow(outage).when(notificationService).processNotification(
                    any(NotificationEvent.class));

            listener.processSystemEvent(context);

            verify(scheduledRetryService).scheduleRetry(any(), any(),
                    eq(NotificationMessageHandler.DATABASE_UNAVAILABLE),
                    anyString(), anyString());
            verify(context, never()).abandon();
            verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        }
    }

    @Test
    void processAccountEvent_retryableFailure_scheduleRefused_atLastAttemptDeadLetters() {
        when(message.getDeliveryCount()).thenReturn(2L); // at max
        when(message.getApplicationProperties()).thenReturn(java.util.Map.of());
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\"," +
                "\"integrationType\":\"EMAIL\",\"email\":\"a@example.com\",\"requestId\":\"r-1\"}]"));

        com.certping.notification.exception.RetryableNotificationException retryable =
                new com.certping.notification.exception.RetryableNotificationException(
                        "ACS_RATE_LIMITED", "throttled", java.time.Duration.ofSeconds(60), null);
        org.mockito.Mockito.doThrow(retryable)
                .when(notificationService).processNotification(
                        any(com.certping.notification.model.NotificationEvent.class));
        when(scheduledRetryService.scheduleRetry(any(), any(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(false); // reschedule budget exhausted

        listener.processAccountEvent(context);

        // Reschedule refused + last-attempt → dead-letter
        verify(context).deadLetter(any(DeadLetterOptions.class));
    }

    private static final String ORDER_EMAIL = "[{\"notificationType\":\"ACCOUNT_EVENT\","
            + "\"notificationAction\":\"CERT_RENEWED_NOT_DEPLOYED\",\"integrationType\":\"EMAIL\","
            + "\"roles\":[\"ORGANIZATION_ADMIN\"],\"organizationId\":7,\"userId\":2,\"includeUser\":true,"
            + "\"deliverOnce\":true,\"requestId\":\"cert-issued-email:9\"}]";

    private static final String MIXED_EMAIL = "["
            + "{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_RENEWED_NOT_DEPLOYED\","
            + "\"integrationType\":\"EMAIL\",\"deliverOnce\":true,\"includeUser\":true,"
            + "\"roles\":[\"ORGANIZATION_ADMIN\"],\"recipients\":[\"old@example.com\"],"
            + "\"requestId\":\"issued-email\"},"
            + "{\"notificationType\":\"ACCOUNT_EVENT\",\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\","
            + "\"integrationType\":\"EMAIL\",\"requestId\":\"standard-email\"}"
            + "]";

    @Test
    void mixedBatchCompletesOnceWhenStandardCopyIsRefused() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService retries = new ScheduledRetryService(sender, 10, 24, Duration.ofDays(7));
        NotificationMessageHandler mixedListener = new NotificationMessageHandler(notificationService, retries,
                undeliveredEmailService, new SyncTaskExecutor(), meterRegistry, deliveryTimeouts);
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getApplicationProperties()).thenReturn(new java.util.HashMap<>(Map.of("RetryCount", 10)));
        when(message.getBody()).thenReturn(MessageBody.fromString(MIXED_EMAIL));
        doThrow(new RetryableNotificationException("MAIL_BUSY", "busy", Duration.ofMinutes(2)))
                .when(notificationService).processNotification(any(NotificationEvent.class));

        mixedListener.processAccountEvent(context);

        ArgumentCaptor<TransportMessage> sent = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender, times(1)).sendMessage(sent.capture());
        assertThat(sent.getValue().getBody().toString()).contains("issued-email").doesNotContain("standard-email", "old@example.com");
        verify(context, times(1)).complete();
        verify(context, never()).abandon();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
    }

    @Test
    void mixedBatchAbandonsWithoutSchedulingDeliverOnceWhenStandardSendFails() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService retries = new ScheduledRetryService(sender, 10, 24, Duration.ofDays(7));
        NotificationMessageHandler mixedListener = new NotificationMessageHandler(notificationService, retries,
                undeliveredEmailService, new SyncTaskExecutor(), meterRegistry, deliveryTimeouts);
        when(message.getApplicationProperties()).thenReturn(new java.util.HashMap<>());
        when(message.getBody()).thenReturn(MessageBody.fromString(MIXED_EMAIL));
        doThrow(new RetryableNotificationException("MAIL_BUSY", "busy", Duration.ofMinutes(2)))
                .when(notificationService).processNotification(any(NotificationEvent.class));
        doThrow(new RuntimeException("bus unavailable")).when(sender).sendMessage(any(TransportMessage.class));

        mixedListener.processAccountEvent(context);

        verify(sender, times(1)).sendMessage(any(TransportMessage.class));
        verify(context).abandon();
        verify(context, never()).complete();
    }

    @Test
    void mixedBatchCompletesOnceWhenDeliverOnceCopyIsRefused() {
        MessageSender sender = mock(MessageSender.class);
        ScheduledRetryService retries = new ScheduledRetryService(sender, 10, 24, Duration.ZERO);
        NotificationMessageHandler mixedListener = new NotificationMessageHandler(notificationService, retries,
                undeliveredEmailService, new SyncTaskExecutor(), meterRegistry, deliveryTimeouts);
        when(message.getApplicationProperties()).thenReturn(new java.util.HashMap<>());
        when(message.getBody()).thenReturn(MessageBody.fromString(MIXED_EMAIL));
        doThrow(new RetryableNotificationException("MAIL_BUSY", "busy", Duration.ofMinutes(2)))
                .when(notificationService).processNotification(any(NotificationEvent.class));

        mixedListener.processAccountEvent(context);

        ArgumentCaptor<TransportMessage> sent = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(sent.capture());
        assertThat(sent.getValue().getBody().toString()).contains("standard-email").doesNotContain("issued-email");
        verify(context, times(1)).complete();
        verify(context, never()).abandon();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        verify(undeliveredEmailService).record(any(NotificationEvent.class), eq(UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED), eq(message));
    }

    private void failDeliverOnce() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getApplicationProperties()).thenReturn(Map.of());
        when(message.getBody()).thenReturn(MessageBody.fromString(ORDER_EMAIL));
        doThrow(new RetryableNotificationException(RecipientDelivery.SEND_FAILED, "mailbox busy", Duration.ofMinutes(2)))
                .when(notificationService).processNotification(any(NotificationEvent.class));
        when(scheduledRetryService.getMaxScheduledRetries()).thenReturn(10);
    }

    @Test
    @SuppressWarnings("unchecked")
    void retryExhaustionAlertsAndKeepsTheRecipientReplayable() {
        failDeliverOnce();
        when(scheduledRetryService.currentRetryCount(message)).thenReturn(10);
        when(scheduledRetryService.scheduleRetries(any(), any()))
                .thenReturn(List.of(ScheduledRetryService.Scheduled.PAST_BUDGET));

        listener.processAccountEvent(context);

        ArgumentCaptor<List<ScheduledRetryService.RetryCopy>> copies = ArgumentCaptor.forClass(List.class);
        verify(scheduledRetryService).scheduleRetries(any(), copies.capture());
        assertThat(copies.getValue()).singleElement().satisfies(copy -> {
            assertThat(copy.policy()).isEqualTo(ScheduledRetryService.Policy.UNTIL_DELIVERED);
            assertThat(copy.bodyJson()).contains("cert-issued-email:9");
        });
        assertThat(meterRegistry.counter(NotificationMessageHandler.UNDELIVERED_METRIC,
                "action", "CERT_RENEWED_NOT_DEPLOYED").count()).isEqualTo(1);
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        verify(context, never()).abandon();
        verify(scheduledRetryService, never()).scheduleRetry(any(), any(), anyString(), anyString(), anyString());
    }

    @Test
    void anUndeliveredEmailIsCountedOnceNotOnEveryHourlyRetry() {
        failDeliverOnce();
        when(scheduledRetryService.currentRetryCount(message)).thenReturn(14);
        when(scheduledRetryService.scheduleRetries(any(), any()))
                .thenReturn(List.of(ScheduledRetryService.Scheduled.PAST_BUDGET));

        listener.processAccountEvent(context);

        assertThat(meterRegistry.find(NotificationMessageHandler.UNDELIVERED_METRIC).counter()).isNull();
    }

    @Test
    void aDeliverOnceEmailPastItsMaximumAgeIsCountedAndDeadLettered() {
        failDeliverOnce();
        when(message.getDeliveryCount()).thenReturn(2L);
        when(scheduledRetryService.scheduleRetries(any(), any()))
                .thenReturn(List.of(ScheduledRetryService.Scheduled.REFUSED));

        listener.processAccountEvent(context);

        assertThat(meterRegistry.counter(NotificationMessageHandler.EXPIRED_METRIC,
                "action", "CERT_RENEWED_NOT_DEPLOYED").count()).isEqualTo(1);
        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(undeliveredEmailService).record(any(NotificationEvent.class), eq(UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED), eq(message));
    }

    @Test
    void aPermanentDeliverOnceFailureIsRecordedBeforeAbandonAndDeadLetter() {
        when(message.getBody()).thenReturn(MessageBody.fromString(ORDER_EMAIL));
        doThrow(new IllegalStateException("claim could not be read"))
                .when(notificationService).processNotification(any(NotificationEvent.class));

        listener.processAccountEvent(context);

        verify(context).abandon();
        verify(undeliveredEmailService).record(any(NotificationEvent.class), eq(UndeliveredEmailService.Outcome.PERMANENT_FAILURE), eq(message));
        assertThat(meterRegistry.counter(NotificationMessageHandler.UNDELIVERED_METRIC,
                "action", "CERT_RENEWED_NOT_DEPLOYED").count()).isEqualTo(1);

        clearInvocations(context, undeliveredEmailService);
        when(message.getDeliveryCount()).thenReturn(2L);
        listener.processAccountEvent(context);

        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(undeliveredEmailService).record(any(NotificationEvent.class), eq(UndeliveredEmailService.Outcome.PERMANENT_FAILURE), eq(message));
    }

    @Test
    void aDeliverOnceEmailDeliveredPastTheBudgetIsCountedRecovered() {
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getApplicationProperties()).thenReturn(Map.of());
        when(message.getBody()).thenReturn(MessageBody.fromString(ORDER_EMAIL));
        when(scheduledRetryService.getMaxScheduledRetries()).thenReturn(10);
        when(scheduledRetryService.currentRetryCount(message)).thenReturn(12);
        when(undeliveredEmailService.resolve(any(NotificationEvent.class))).thenReturn(true);

        listener.processAccountEvent(context);

        verify(context).complete();
        assertThat(meterRegistry.counter(NotificationMessageHandler.RECOVERED_METRIC,
                "action", "CERT_RENEWED_NOT_DEPLOYED").count()).isEqualTo(1);
    }

    @Test
    void noRecipientDoesNotBecomeUndelivered() {
        when(message.getBody()).thenReturn(MessageBody.fromString(ORDER_EMAIL));

        listener.processAccountEvent(context);

        verify(context).complete();
        verify(undeliveredEmailService, never()).record(any(NotificationEvent.class), any(UndeliveredEmailService.Outcome.class), any());
        assertThat(meterRegistry.find(NotificationMessageHandler.UNDELIVERED_METRIC).counter()).isNull();
    }

    @Test
    void aNoRecipientRetryDoesNotBecomeUndeliveredWhenItsBudgetEnds() {
        when(message.getBody()).thenReturn(MessageBody.fromString(ORDER_EMAIL));
        when(message.getApplicationProperties()).thenReturn(Map.of("LastRetryReason", NotificationService.NO_RECIPIENT));
        doThrow(new RetryableNotificationException(NotificationService.NO_RECIPIENT, "nobody", Duration.ofMinutes(30)))
                .when(notificationService).processNotification(any(NotificationEvent.class));

        listener.processAccountEvent(context);

        verifyNoInteractions(undeliveredEmailService);
        assertThat(meterRegistry.find(NotificationMessageHandler.UNDELIVERED_METRIC).counter()).isNull();
    }

    @Test
    void anEventOutlastingItsDeadlineIsRedeliveredWithoutAnAlert() {
        when(message.getBody()).thenReturn(MessageBody.fromString(ORDER_EMAIL));
        when(deliveryTimeouts.eventDeadline()).thenReturn(Duration.ofMillis(1));
        NotificationMessageHandler stalledListener = new NotificationMessageHandler(notificationService,
                scheduledRetryService, undeliveredEmailService, task -> {}, meterRegistry, deliveryTimeouts);

        stalledListener.processAccountEvent(context);

        verify(context).abandon();
        verify(context, never()).complete();
        verify(undeliveredEmailService, never()).record(any(), any(), any());
    }

    @Test
    void anEmailRefusedByEveryRemainingRecipientIsRecordedAndCompleted() {
        when(message.getBody()).thenReturn(MessageBody.fromString(ORDER_EMAIL));
        when(message.getApplicationProperties()).thenReturn(Map.of());
        doThrow(new RecipientsRefusedException(1)).when(notificationService).processNotification(any(NotificationEvent.class));

        listener.processAccountEvent(context);

        verify(undeliveredEmailService).record(any(NotificationEvent.class),
                eq(UndeliveredEmailService.Outcome.PERMANENT_FAILURE), eq(message));
        verify(scheduledRetryService, never()).scheduleRetries(any(), any());
        verify(context).complete();
        verify(context, never()).abandon();
        verify(context, never()).deadLetter(any());
    }
}
