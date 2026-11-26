// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * An outbound notification message: body, message id, application properties, schedule and time
 * to live. A plain value object; {@link MessageSender} decides how it travels.
 */
public class TransportMessage {

    private final MessageBody body;
    private final Map<String, Object> applicationProperties = new HashMap<>();
    private String messageId;
    private String correlationId;
    private String subject;
    private String contentType;
    private Duration timeToLive;
    private OffsetDateTime scheduledEnqueueTime;

    public TransportMessage(MessageBody body) {
        this.body = Objects.requireNonNull(body, "body");
    }

    public TransportMessage(String body) {
        this(MessageBody.fromString(body));
    }

    public TransportMessage(byte[] body) {
        this(MessageBody.fromBytes(body));
    }

    public MessageBody getBody() {
        return body;
    }

    /** Mutable: callers put properties straight into it. */
    public Map<String, Object> getApplicationProperties() {
        return applicationProperties;
    }

    public String getMessageId() {
        return messageId;
    }

    public TransportMessage setMessageId(String messageId) {
        this.messageId = messageId;
        return this;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public TransportMessage setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public TransportMessage setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    public String getContentType() {
        return contentType;
    }

    public TransportMessage setContentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    public Duration getTimeToLive() {
        return timeToLive;
    }

    public TransportMessage setTimeToLive(Duration timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }

    public OffsetDateTime getScheduledEnqueueTime() {
        return scheduledEnqueueTime;
    }

    public TransportMessage setScheduledEnqueueTime(OffsetDateTime scheduledEnqueueTime) {
        this.scheduledEnqueueTime = scheduledEnqueueTime;
        return this;
    }
}
