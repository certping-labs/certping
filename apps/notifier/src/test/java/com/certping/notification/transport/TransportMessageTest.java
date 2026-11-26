// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TransportMessageTest {

    @Test
    void bodyRoundTripsTextAndBytesAsUtf8() {
        String text = "[{\"name\":\"café ✓\"}]";
        MessageBody fromText = MessageBody.fromString(text);
        assertThat(fromText.toString()).isEqualTo(text);
        assertThat(fromText.toBytes()).isEqualTo(text.getBytes(StandardCharsets.UTF_8));

        MessageBody fromBytes = MessageBody.fromBytes(text.getBytes(StandardCharsets.UTF_8));
        assertThat(fromBytes.toString()).isEqualTo(text);
        assertThat(fromBytes).isEqualTo(fromText).hasSameHashCodeAs(fromText);
    }

    @Test
    void bodyIsImmutable() {
        byte[] source = "abc".getBytes(StandardCharsets.UTF_8);
        MessageBody body = MessageBody.fromBytes(source);
        source[0] = 'x';
        body.toBytes()[1] = 'y';
        assertThat(body.toString()).isEqualTo("abc");
    }

    @Test
    void bodyRejectsNull() {
        assertThatThrownBy(() -> MessageBody.fromString(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> MessageBody.fromBytes(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void messageCarriesEveryField() {
        OffsetDateTime at = OffsetDateTime.parse("2030-01-01T00:00:00Z");
        TransportMessage message = new TransportMessage("{}")
                .setMessageId("m-1")
                .setCorrelationId("c-1")
                .setSubject("s")
                .setContentType("application/json")
                .setTimeToLive(Duration.ofMinutes(5))
                .setScheduledEnqueueTime(at);
        message.getApplicationProperties().put("notificationType", "SYSTEM_EVENT");

        assertThat(message.getBody().toString()).isEqualTo("{}");
        assertThat(message.getMessageId()).isEqualTo("m-1");
        assertThat(message.getCorrelationId()).isEqualTo("c-1");
        assertThat(message.getSubject()).isEqualTo("s");
        assertThat(message.getContentType()).isEqualTo("application/json");
        assertThat(message.getTimeToLive()).isEqualTo(Duration.ofMinutes(5));
        assertThat(message.getScheduledEnqueueTime()).isEqualTo(at);
        assertThat(message.getApplicationProperties()).containsEntry("notificationType", "SYSTEM_EVENT");
        assertThat(new TransportMessage("x".getBytes(StandardCharsets.UTF_8)).getBody().toString()).isEqualTo("x");
        assertThat(new TransportMessage(MessageBody.fromString("y")).getApplicationProperties()).isEmpty();
    }

    @Test
    void deadLetterOptionsKeepReasonAndDescription() {
        DeadLetterOptions options = new DeadLetterOptions()
                .setDeadLetterReason("MaxDeliveryCountExceeded")
                .setDeadLetterErrorDescription("too many");
        assertThat(options.getDeadLetterReason()).isEqualTo("MaxDeliveryCountExceeded");
        assertThat(options.getDeadLetterErrorDescription()).isEqualTo("too many");
    }
}
