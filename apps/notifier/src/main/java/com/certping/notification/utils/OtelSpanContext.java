// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.util;

import io.opentelemetry.api.trace.Span;

import java.util.Map;

/**
 * Enriches the active OpenTelemetry span with notification correlation attributes.
 *
 * <p>Runtime tracing is provided by the OpenTelemetry Java agent; this class only calls
 * {@link Span#current()} to attach request-scoped ids aligned with the server
 * and the agent.
 */
public final class OtelSpanContext {

    private OtelSpanContext() {
    }

    /** HTTP entry ({@code /api/**}) — after context is seeded in {@code RequestContextInterceptor}. */
    public static void enrichHttp(String requestId, String correlationId) {
        Span span = Span.current();
        setIfPresent(span, "request.id", requestId);
        setIfPresent(span, "correlation.id", correlationId);
    }

    /** Inbound message batch, before individual events are processed. */
    public static void enrichInboundBatch(String requestId, String correlationId, String messageId) {
        Span span = Span.current();
        setIfPresent(span, "request.id", requestId);
        setIfPresent(span, "correlation.id", correlationId);
        setIfPresent(span, "messaging.message.id", messageId);
    }

    /** Individual notification event — email delivery span. */
    public static void enrichNotificationConsume(String requestId,
                                                 String correlationId,
                                                 String organizationId,
                                                 String certificateXref,
                                                 String notificationAction,
                                                 String notificationType,
                                                 String messageId,
                                                 String userId) {
        Span span = Span.current();
        setIfPresent(span, "request.id", requestId);
        setIfPresent(span, "correlation.id", correlationId);
        setIfPresent(span, "organization.id", organizationId);
        setIfPresent(span, "certificate.xref", certificateXref);
        setIfPresent(span, "message.type", notificationAction);
        setIfPresent(span, "notification.type", notificationType);
        setIfPresent(span, "messaging.message.id", messageId);
        setIfPresent(span, "user.id", userId);
    }

    public static String fieldAsString(Map<String, Object> fields, String key) {
        if (fields == null || key == null) {
            return null;
        }
        Object value = fields.get(key);
        return value != null ? value.toString() : null;
    }

    private static void setIfPresent(Span span, String key, String value) {
        if (value != null && !value.isEmpty() && !"unknown".equals(value)) {
            span.setAttribute(key, value);
        }
    }
}
