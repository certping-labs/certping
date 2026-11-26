// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.DeadLetterOptions;
import com.certping.notification.model.NotificationEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.concurrent.ConcurrentTaskExecutor;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A message is handled, on every thread that handles it, under the ids its publisher sent. */
class NotificationMessageHandlerTracingTest {

    private static final String EVENT = "{\"notificationType\":\"ACCOUNT_EVENT\","
            + "\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\",\"integrationType\":\"EMAIL\","
            + "\"email\":\"ada@example.com\",\"recipients\":[\"ada@example.com\",\"grace@example.com\"]%s}";

    private final NotificationService notificationService = mock(NotificationService.class);
    private final InboundContext context = mock(InboundContext.class);
    private final InboundMessage message = mock(InboundMessage.class);
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger listenerLogger = (Logger) LoggerFactory.getLogger(NotificationMessageHandler.class);

    @BeforeEach
    void setUp() {
        when(context.getMessage()).thenReturn(message);
        when(message.getMessageId()).thenReturn("msg-abc123");
        logs.start();
        listenerLogger.addAppender(logs);
    }

    @AfterEach
    void tearDown() {
        listenerLogger.detachAppender(logs);
        worker.shutdownNow();
    }

    private NotificationMessageHandler listener(TaskExecutor executor) {
        DeliveryTimeouts timeouts = mock(DeliveryTimeouts.class);
        when(timeouts.eventDeadline()).thenReturn(Duration.ofSeconds(30));
        return new NotificationMessageHandler(notificationService, mock(ScheduledRetryService.class),
                mock(UndeliveredEmailService.class), executor, new SimpleMeterRegistry(), timeouts);
    }

    private void deliver(Map<String, Object> properties, String eventFields) {
        when(message.getApplicationProperties()).thenReturn(properties);
        when(message.getBody()).thenReturn(MessageBody.fromString("[" + EVENT.formatted(eventFields) + "]"));
    }

    /** The logging context as the delivery of an event sees it. */
    private AtomicReference<Map<String, String>> contextAtDelivery() {
        AtomicReference<Map<String, String>> seen = new AtomicReference<>();
        doAnswer(call -> {
            seen.set(MDC.getCopyOfContextMap());
            return null;
        }).when(notificationService).processNotification(any(NotificationEvent.class));
        return seen;
    }

    @Test
    void theApplicationPropertiesAndTheNotificationKeyAreTheLoggingContext() {
        deliver(Map.of("correlationId", "corr-http-1", "requestId", "req-http-1"),
                ",\"notificationKey\":\"cert-issued-email:5\",\"requestId\":\"cert-issued-email:5\","
                        + "\"correlationId\":\"corr-body\"");
        AtomicReference<Map<String, String>> seen = contextAtDelivery();

        listener(new SyncTaskExecutor()).processAccountEvent(context);

        assertThat(seen.get()).containsEntry("correlationId", "corr-http-1").containsEntry("requestId", "req-http-1")
                .containsEntry("notificationKey", "cert-issued-email:5");
    }

    @Test
    void aPublisherWithoutPropertiesOrNotificationKeyFallsBackToTheBody() {
        deliver(Map.of(), ",\"requestId\":\"r-1\",\"correlationId\":\"corr-body\"");
        AtomicReference<Map<String, String>> seen = contextAtDelivery();

        listener(new SyncTaskExecutor()).processAccountEvent(context);

        assertThat(seen.get()).containsEntry("correlationId", "corr-body").containsEntry("requestId", "r-1")
                .containsEntry("notificationKey", "r-1");
        assertThat(NotificationEvent.builder().requestId("r-1").build().idempotencyKey()).isEqualTo("r-1");
        assertThat(NotificationEvent.builder().requestId("r-1").notificationKey("key-1").build().idempotencyKey())
                .isEqualTo("key-1");
    }

    @Test
    void anIdThatIsNotValidNeverReachesTheLoggingContext() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("correlationId", "corr 1\nlevel=ERROR forged");
        properties.put("requestId", "r".repeat(129));
        deliver(properties, ",\"notificationKey\":\"key-1\"");
        AtomicReference<Map<String, String>> seen = contextAtDelivery();

        listener(new SyncTaskExecutor()).processAccountEvent(context);

        assertThat(seen.get()).containsEntry("notificationKey", "key-1")
                .doesNotContainKeys("correlationId", "requestId");
        assertThat(logs.list).noneMatch(line -> line.getFormattedMessage().contains("forged"));
    }

    @Test
    void theContextCrossesToTheExecutorThreadAndIsClearedOnBoth() throws Exception {
        deliver(Map.of("correlationId", "corr-http-1", "requestId", "req-http-1"), ",\"notificationKey\":\"key-1\"");
        AtomicReference<Map<String, String>> seen = contextAtDelivery();
        AtomicReference<Thread> deliveredOn = new AtomicReference<>();
        doAnswer(call -> {
            seen.set(MDC.getCopyOfContextMap());
            deliveredOn.set(Thread.currentThread());
            return null;
        }).when(notificationService).processNotification(any(NotificationEvent.class));

        listener(new ConcurrentTaskExecutor(worker)).processAccountEvent(context);

        assertThat(deliveredOn.get()).isNotSameAs(Thread.currentThread());
        assertThat(seen.get()).containsEntry("correlationId", "corr-http-1").containsEntry("requestId", "req-http-1")
                .containsEntry("notificationKey", "key-1");
        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
        assertThat(worker.submit(MDC::getCopyOfContextMap).get()).isNullOrEmpty();
    }

    @Test
    void aHandledMessageWritesOneCanonicalLineNamingNoRecipient() {
        deliver(Map.of("correlationId", "corr-http-1", "requestId", "req-http-1"), ",\"notificationKey\":\"key-1\"");

        listener(new ConcurrentTaskExecutor(worker)).processAccountEvent(context);

        verify(context).complete();
        List<ILoggingEvent> canonical = logs.list.stream()
                .filter(line -> line.getFormattedMessage().contains("notification message handled")).toList();
        assertThat(canonical).hasSize(1);
        assertThat(canonical.get(0).getFormattedMessage())
                .contains("outcome=completed", "type=account", "notificationKey=key-1", "events=1",
                        "recipients=2", "durationMs=");
        assertThat(canonical.get(0).getMDCPropertyMap()).containsEntry("correlationId", "corr-http-1")
                .containsEntry("requestId", "req-http-1");
        assertThat(logs.list).noneMatch(line -> line.getFormattedMessage().contains("example.com"));
    }

    @Test
    void aKeyThatIsNotAValidIdIsDeliveredUnchangedAndLoggedOnlyAsADigest() {
        deliver(Map.of(), ",\"notificationKey\":\"key 1 forged\",\"deliverOnce\":true");
        AtomicReference<Map<String, String>> seen = contextAtDelivery();
        AtomicReference<String> delivered = new AtomicReference<>();
        doAnswer(call -> {
            seen.set(MDC.getCopyOfContextMap());
            delivered.set(call.<NotificationEvent>getArgument(0).idempotencyKey());
            return null;
        }).when(notificationService).processNotification(any(NotificationEvent.class));

        listener(new ConcurrentTaskExecutor(worker)).processAccountEvent(context);

        assertThat(delivered.get()).isEqualTo("key 1 forged");
        assertThat(seen.get().get("notificationKey")).startsWith("sha256:");
        assertThat(logs.list).noneMatch(line -> line.getFormattedMessage().contains("forged"));
        assertThat(logs.list).anyMatch(line -> line.getFormattedMessage().contains("notificationKey=sha256:"));
    }

    @Test
    void aMessagePastItsDeliveriesIsDeadLetteredUnderItsKeyWhetherOrNotItsBodyReads() {
        when(message.getDeliveryCount()).thenReturn(3L);
        deliver(Map.of(), ",\"notificationKey\":\"key-1\"");

        listener(new SyncTaskExecutor()).processAccountEvent(context);

        when(message.getBody()).thenReturn(MessageBody.fromString("not json"));
        listener(new SyncTaskExecutor()).processAccountEvent(context);

        verify(context, times(2)).deadLetter(any(DeadLetterOptions.class));
        assertThat(logs.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(line -> line.contains("notification message handled")))
                .satisfiesExactly(
                        read -> assertThat(read).contains("outcome=dead_lettered", "notificationKey=key-1"),
                        unread -> assertThat(unread).contains("outcome=dead_lettered", "notificationKey=none"));
    }
}
