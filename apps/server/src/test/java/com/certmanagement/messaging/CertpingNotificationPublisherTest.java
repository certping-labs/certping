// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.InboundSenders;
import com.certmanagement.integration.IntegrationNotificationClient;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.core.JacksonException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/** Unit tests for {@link CertpingNotificationPublisher}. */
class CertpingNotificationPublisherTest {

    private MessageSender sender;
    private ObjectMapper objectMapper;
    private IntegrationNotificationClient integrationClient;
    private CertpingNotificationPublisher publisher;

    @BeforeEach
    void setUp() {
        sender = mock(MessageSender.class);
        objectMapper = JsonMapper.builderWithJackson2Defaults().build();
        integrationClient = mock(IntegrationNotificationClient.class);
        publisher = new CertpingNotificationPublisher(sender, objectMapper, integrationClient);
    }

    @Test
    void publishesEventAndDispatchesToIntegrations() {
        Map<String, Object> details = new HashMap<>();
        details.put("domain", "acme.test");
        details.put("requestId", "req-99");

        publisher.publish("CERT_ISSUANCE_SUCCESS", "55", "xref-1", details);

        ArgumentCaptor<TransportMessage> msg = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(msg.capture());
        TransportMessage sent = msg.getValue();
        assertThat(sent.getApplicationProperties())
                .containsEntry("notificationType", "ACCOUNT_EVENT")
                .containsEntry("source", "certping-cert-manager")
                .containsEntry("organizationId", "55");
        // Stable message id derived from requestId.
        assertThat(sent.getMessageId()).startsWith("msg-");
        assertThat(sent.getBody().toString())
                .contains("CERT_ISSUANCE_SUCCESS")
                .contains("certificateXref")
                .contains("acme.test");

        verify(integrationClient).dispatch(eq("55"), eq("CERT_ISSUANCE_SUCCESS"), eq("xref-1"), anyMap());
    }

    @Test
    void usesNanoTimeMessageIdWhenNoRequestId() {
        publisher.publish("CERT_RENEWAL_FAILED", "1", null, null);

        ArgumentCaptor<TransportMessage> msg = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(msg.capture());
        assertThat(msg.getValue().getMessageId()).startsWith("msg-");
    }

    @Test
    void wrapsSerializationFailureAsRuntimeException() throws Exception {
        ObjectMapper boom = mock(ObjectMapper.class);
        when(boom.writeValueAsString(any())).thenThrow(new JacksonException("nope") {});
        CertpingNotificationPublisher broken =
                new CertpingNotificationPublisher(sender, boom, integrationClient);

        assertThatThrownBy(() -> broken.publish("A", "1", "x", Map.of()))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to serialize notification payload");
        verify(sender, never()).sendMessage(any());
    }
}
