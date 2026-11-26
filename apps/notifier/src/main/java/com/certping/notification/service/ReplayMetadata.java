// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.TransportMessage;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.utils.MessageIds;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * What an undelivered email's recorded payload keeps of its message, and a replay publishes again:
 * where its retry chain stands, so a replay continues the chain rather than starting a new one, and
 * the ids of the request it was published for. A payload recorded without those ids replays with
 * the event's own correlation id and no request id or traceparent.
 */
record ReplayMetadata(String firstRetryAt, int retryCount, int replayCount, MessageIds origin) {

    private static final String ORIGIN_CORRELATION_ID = "originCorrelationId";
    private static final String ORIGIN_REQUEST_ID = "originRequestId";
    private static final String ORIGIN_TRACEPARENT = "originTraceparent";

    private static final String FIRST_RETRY_AT = "firstRetryAt";
    private static final String RETRY_COUNT = "retryCount";
    private static final String REPLAY_COUNT = "replayCount";
    private static final String REPLAY_COUNT_PROPERTY = "ReplayCount";

    static ReplayMetadata from(InboundMessage message) {
        Map<String, Object> properties = message == null || message.getApplicationProperties() == null
                ? Map.of() : message.getApplicationProperties();
        return new ReplayMetadata(String.valueOf(properties.getOrDefault(
                ScheduledRetryService.PROP_FIRST_RETRY_AT, Instant.now().toString())),
                count(properties, ScheduledRetryService.PROP_RETRY_COUNT),
                count(properties, REPLAY_COUNT_PROPERTY), MessageIds.from(properties));
    }

    static ReplayMetadata from(JsonNode payload) {
        JsonNode metadata = payload.get(0);
        Map<String, Object> origin = new HashMap<>();
        origin.put(MessageIds.CORRELATION_ID, metadata.path(
                metadata.hasNonNull(ORIGIN_CORRELATION_ID) ? ORIGIN_CORRELATION_ID : MessageIds.CORRELATION_ID).asString(null));
        origin.put(MessageIds.REQUEST_ID, metadata.path(ORIGIN_REQUEST_ID).asString(null));
        origin.put(MessageIds.TRACEPARENT, metadata.path(ORIGIN_TRACEPARENT).asString(null));
        return new ReplayMetadata(metadata.path(FIRST_RETRY_AT).asString(),
                metadata.path(RETRY_COUNT).asInt(), metadata.path(REPLAY_COUNT).asInt(), MessageIds.from(origin));
    }

    void writeTo(ObjectNode event) {
        event.put(FIRST_RETRY_AT, firstRetryAt);
        event.put(RETRY_COUNT, retryCount);
        event.put(REPLAY_COUNT, replayCount);
        putIfPresent(event, ORIGIN_CORRELATION_ID, origin.correlationId());
        putIfPresent(event, ORIGIN_REQUEST_ID, origin.requestId());
        putIfPresent(event, ORIGIN_TRACEPARENT, origin.traceparent());
    }

    void writeTo(TransportMessage message) {
        message.getApplicationProperties().put(ScheduledRetryService.PROP_FIRST_RETRY_AT, firstRetryAt);
        message.getApplicationProperties().put(ScheduledRetryService.PROP_RETRY_COUNT, retryCount);
        message.getApplicationProperties().put(REPLAY_COUNT_PROPERTY, replayCount);
        origin.writeTo(message.getApplicationProperties());
    }

    private static void putIfPresent(ObjectNode event, String field, String value) {
        if (value != null) {
            event.put(field, value);
        }
    }

    private static int count(Map<String, Object> properties, String key) {
        Object value = properties.get(key);
        return value instanceof Number number ? number.intValue() : 0;
    }
}
