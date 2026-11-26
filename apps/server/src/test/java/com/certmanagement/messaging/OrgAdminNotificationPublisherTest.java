// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.TransportMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link OrgAdminNotificationPublisher}. */
class OrgAdminNotificationPublisherTest {

    private MessageSender sender;
    private OrgAdminNotificationPublisher publisher;

    @BeforeEach
    void setUp() {
        sender = mock(MessageSender.class);
        publisher = new OrgAdminNotificationPublisher(sender, JsonMapper.builderWithJackson2Defaults().build());
    }

    private TransportMessage sentMessage() {
        ArgumentCaptor<TransportMessage> msg = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(msg.capture());
        return msg.getValue();
    }

    @Test
    void publishesDeliverOnceEventToOrgAdmins() {
        publisher.publishOnceToOrgAdmins("FEATURE_PAUSED", "org-7", "feature-lifecycle",
                Map.of("featureName", "Auto renew"), "feature-paused:org-7:auto-renew");

        TransportMessage sent = sentMessage();
        assertThat(sent.getMessageId())
                .isEqualTo(OrgAdminNotificationPublisher.messageId("FEATURE_PAUSED", "feature-paused:org-7:auto-renew"))
                .startsWith("org-")
                .hasSize(4 + 24);
        assertThat(sent.getApplicationProperties())
                .containsEntry("notificationType", OrgAdminNotificationPublisher.NOTIFICATION_TYPE)
                .containsEntry("source", "feature-lifecycle")
                .containsEntry("organizationId", "org-7");
        assertThat(sent.getBody().toString())
                .contains("\"notificationAction\":\"FEATURE_PAUSED\"")
                .contains("\"roles\":[\"" + OrgAdminNotificationPublisher.ROLE + "\"]")
                .contains("\"requestId\":\"feature-paused:org-7:auto-renew\"")
                .contains("\"deliverOnce\":true")
                .contains("\"integrationType\":\"EMAIL\"")
                .contains("Auto renew");
    }

    @Test
    void nullOrganizationAndTemplateFieldsStillPublish() {
        publisher.publishOnceToOrgAdmins("DNS_KEY_EXPIRING", null, "dns-keys", null, "key-1");

        TransportMessage sent = sentMessage();
        assertThat(sent.getApplicationProperties()).doesNotContainKey("organizationId");
        assertThat(sent.getBody().toString()).contains("\"templateFields\":{}");
    }

    @Test
    void sameActionAndKeyGiveTheSameMessageId() {
        publisher.publishOnceToOrgAdmins("A", "o", "s", Map.of(), "k");
        publisher.publishOnceToOrgAdmins("A", "o", "s", Map.of(), "k");

        ArgumentCaptor<TransportMessage> msg = ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender, times(2)).sendMessage(msg.capture());
        assertThat(msg.getAllValues().get(0).getMessageId())
                .isEqualTo(msg.getAllValues().get(1).getMessageId());
    }

    @Test
    void messageIdSeparatesActionsAndKeysAndToleratesNulls() {
        assertThat(OrgAdminNotificationPublisher.messageId("A", "k"))
                .isNotEqualTo(OrgAdminNotificationPublisher.messageId("B", "k"))
                .isNotEqualTo(OrgAdminNotificationPublisher.messageId("A", "j"));
        assertThat(OrgAdminNotificationPublisher.messageId(null, null))
                .isEqualTo(OrgAdminNotificationPublisher.messageId("", ""))
                .matches("org-[0-9a-f]{24}");
    }

    @Test
    void serializationFailureIsWrappedAndNothingIsSent() throws Exception {
        ObjectMapper boom = mock(ObjectMapper.class);
        when(boom.writeValueAsString(any())).thenThrow(new JacksonException("x") {});
        OrgAdminNotificationPublisher broken = new OrgAdminNotificationPublisher(sender, boom);

        assertThatThrownBy(() -> broken.publishOnceToOrgAdmins("FEATURE_RESUMED", "o", "s", Map.of(), "k"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("action=FEATURE_RESUMED");
        verify(sender, never()).sendMessage(any());
    }
}
