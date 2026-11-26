// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.config.QueueAlertProperties;
import com.certmanagement.repository.UserRepository;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Covers {@link OperationalAlertPublisher#publishQueueAlert} including the no-sender skip,
 * the no-recipients skip, the happy-path publish, and the DB-failure fallback in
 * {@code resolveRecipients()}.
 */
@ExtendWith(MockitoExtension.class)
class OperationalAlertPublisherMoreTest {

    @Mock private QueueAlertProperties queueAlertProperties;
    @Mock private UserRepository userRepository;

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private OperationalAlertPublisher publisher;
    private MessageSender sender;

    @BeforeEach
    void setUp() {
        publisher = new OperationalAlertPublisher(objectMapper, queueAlertProperties, userRepository);
        sender = mock(MessageSender.class);
        ReflectionTestUtils.setField(publisher, "environment", "test");
        ReflectionTestUtils.setField(publisher, "fallbackSuperAdminEmail", "fallback@example.com");
    }

    private void withSender() {
        ReflectionTestUtils.setField(publisher, "certNotificationsSender", sender);
    }

    @Test
    void publishQueueAlert_noSender_skips() {
        // certNotificationsSender left null
        publisher.publishQueueAlert("SYSTEM_DLQ_ALERT", "q1", "QUEUE", "DLQ", 10, 5, "CRITICAL");
        verifyNoInteractions(userRepository);
    }

    @Test
    void publishQueueAlert_noRecipients_skips() {
        withSender();
        when(userRepository.findActivePlatformRoleEmails(anyString())).thenReturn(List.of());
        ReflectionTestUtils.setField(publisher, "fallbackSuperAdminEmail", "   ");

        publisher.publishQueueAlert("SYSTEM_DLQ_ALERT", "q1", "QUEUE", "DLQ", 10, 5, "CRITICAL");

        verify(sender, never()).sendMessage(any());
    }

    @Test
    void publishQueueAlert_withDbSuperAdmins_publishesWithFields() {
        withSender();
        when(userRepository.findActivePlatformRoleEmails(anyString()))
                .thenReturn(List.of("admin@example.com"));
        when(queueAlertProperties.getDashboardUrl()).thenReturn("https://dash");

        publisher.publishQueueAlert("SYSTEM_QUEUE_DEPTH_WARNING", "topic/sub", "SUBSCRIPTION",
                "ACTIVE", 100, 50, "WARNING");

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(captor.capture());
        TransportMessage msg = captor.getValue();
        assertThat(msg.getApplicationProperties()).containsEntry("notificationType", "SYSTEM_EVENT");
        assertThat(msg.getMessageId()).startsWith("msg-qalert-system-queue-depth-warning-");
        String body = msg.getBody().toString();
        assertThat(body).contains("admin@example.com");
        assertThat(body).contains("SYSTEM_QUEUE_DEPTH_WARNING");
        assertThat(body).contains("https://dash");
        assertThat(body).contains("\"environment\":\"test\"");
    }

    @Test
    void publishQueueAlert_dbQueryFails_fallsBackToConfiguredEmail() {
        withSender();
        when(userRepository.findActivePlatformRoleEmails(anyString()))
                .thenThrow(new RuntimeException("db down"));
        when(queueAlertProperties.getDashboardUrl()).thenReturn("https://dash");

        publisher.publishQueueAlert("SYSTEM_QUEUE_ALERT_RESOLVED", "q2", "QUEUE", "DLQ", 0, 5, "INFO");

        ArgumentCaptor<TransportMessage> captor = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(captor.capture());
        assertThat(captor.getValue().getBody().toString()).contains("fallback@example.com");
    }
}
