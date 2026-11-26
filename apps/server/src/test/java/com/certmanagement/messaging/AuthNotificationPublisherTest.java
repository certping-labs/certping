// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.InboundSenders;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.core.JacksonException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/** Unit tests for {@link AuthNotificationPublisher}. */
class AuthNotificationPublisherTest {

    private MessageSender sender;
    private AuthNotificationPublisher publisher;

    @BeforeEach
    void setUp() {
        sender = mock(MessageSender.class);
        publisher = new AuthNotificationPublisher(sender, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void publishesWithStableMessageIdFromRequestId() {
        publisher.publish("RESET_PASSWORD", "user@acme.test", 42, 7L,
                Map.of("resetLink", "https://acme.test/reset"), "req-abc");

        ArgumentCaptor<TransportMessage> msg = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(msg.capture());
        TransportMessage sent = msg.getValue();
        assertThat(sent.getMessageId()).startsWith("auth-");
        assertThat(sent.getApplicationProperties())
                .containsEntry("notificationType", "ACCOUNT_EVENT")
                .containsEntry("organizationId", "7");
        assertThat(sent.getBody().toString())
                .contains("RESET_PASSWORD")
                .contains("user@acme.test")
                .contains("resetLink");
    }

    @Test
    void messageIdIsDeterministicForSameInputs() {
        publisher.publish("RESET", "u@a.test", 1, 1L, Map.of(), "req-1");
        publisher.publish("RESET", "u@a.test", 1, 1L, Map.of(), "req-1");

        ArgumentCaptor<TransportMessage> msg = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender, times(2)).sendMessage(msg.capture());
        assertThat(msg.getAllValues().get(0).getMessageId())
                .isEqualTo(msg.getAllValues().get(1).getMessageId());
    }

    @Test
    void nullOrgIdAndNullRequestIdStillPublishes() {
        publisher.publish("RESET", "u@a.test", null, null, null, null);

        ArgumentCaptor<TransportMessage> msg = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(msg.capture());
        assertThat(msg.getValue().getApplicationProperties()).doesNotContainKey("organizationId");
    }

    @Test
    void wrapsSerializationFailure() throws Exception {
        ObjectMapper boom = mock(ObjectMapper.class);
        when(boom.writeValueAsString(any())).thenThrow(new JacksonException("x") {});
        AuthNotificationPublisher broken = new AuthNotificationPublisher(sender, boom);

        assertThatThrownBy(() -> broken.publish("A", "e@x.test", 1, 1L, Map.of(), "r"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to serialize auth notification");
        verify(sender, never()).sendMessage(any());
    }
}
