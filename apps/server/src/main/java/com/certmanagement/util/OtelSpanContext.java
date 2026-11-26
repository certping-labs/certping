// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import io.opentelemetry.api.trace.Span;

import java.util.Map;

/**
 * Enriches the active OpenTelemetry span with business correlation attributes.
 *
 * <p>Runtime tracing is provided by the OpenTelemetry Java agent; this class only calls
 * {@link Span#current()} to attach request-scoped ids that mirror SLF4J MDC and align
 * attribute names with certping-agent.
 */
public final class OtelSpanContext {

    private OtelSpanContext() {
    }

    /** HTTP entry ({@code /api/**}) — after MDC is seeded in {@code RequestContextInterceptor}. */
    public static void enrichHttp(String requestId,
                                  String correlationId,
                                  String organizationId,
                                  String userId) {
        Span span = Span.current();
        setIfPresent(span, "request.id", requestId);
        setIfPresent(span, "correlation.id", correlationId);
        setIfPresent(span, "organization.id", organizationId);
        setIfPresent(span, "user.id", userId);
    }

    /** Inbound agent message: an agent response on cert-agent-outbound. */
    public static void enrichAgentMessage(String requestId,
                                            String correlationId,
                                          String organizationId,
                                          String certificateXref,
                                          String messageType,
                                          String messageId) {
        Span span = Span.current();
        setIfPresent(span, "request.id", requestId);
        setIfPresent(span, "correlation.id", correlationId);
        setIfPresent(span, "organization.id", organizationId);
        setIfPresent(span, "certificate.xref", certificateXref);
        setIfPresent(span, "message.type", messageType);
        setIfPresent(span, "messaging.message.id", messageId);
    }

    /** Outbound agent command: published to an agent inbound queue. */
    public static void enrichAgentPublish(String requestId,
                                            String correlationId,
                                            String organizationId,
                                            String certificateXref,
                                            String messageType,
                                            String messageId) {
        enrichAgentMessage(requestId, correlationId, organizationId, certificateXref, messageType, messageId);
    }

    /** Scheduled cron entry — only {@code requestId} is minted for background ticks. */
    public static void enrichScheduledTick(String requestId) {
        setIfPresent(Span.current(), "request.id", requestId);
    }

    /** Outbound notification events to the notifier via the notifications channel. */
    public static void enrichNotificationPublish(String requestId,
                                                 String correlationId,
                                                 String organizationId,
                                                 String certificateXref,
                                                 String notificationAction,
                                                 String notificationType,
                                                 String messageId) {
        Span span = Span.current();
        setIfPresent(span, "request.id", requestId);
        setIfPresent(span, "correlation.id", correlationId);
        setIfPresent(span, "organization.id", organizationId);
        setIfPresent(span, "certificate.xref", certificateXref);
        setIfPresent(span, "message.type", notificationAction);
        setIfPresent(span, "notification.type", notificationType);
        setIfPresent(span, "messaging.message.id", messageId);
    }

    /** Inbound notification event consumed by certping-notifier. */
    public static void enrichNotificationConsume(String requestId,
                                                 String correlationId,
                                                 String organizationId,
                                                 String certificateXref,
                                                 String notificationAction,
                                                 String notificationType,
                                                 String messageId,
                                                 String userId) {
        enrichNotificationPublish(requestId, correlationId, organizationId, certificateXref,
                notificationAction, notificationType, messageId);
        setIfPresent(Span.current(), "user.id", userId);
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
