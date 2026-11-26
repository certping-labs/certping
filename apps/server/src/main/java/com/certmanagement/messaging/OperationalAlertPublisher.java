// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.config.QueueAlertProperties;
import com.certmanagement.enums.EventSource;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.Permissions;
import com.certmanagement.util.MdcIds;
import com.certmanagement.util.OtelSpanContext;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Publishes operational queue-depth / DLQ alerts to the platform super admins through the
 * {@code notifications} channel the notifier reads, with recipient handling tailored to infra alerts:
 *
 * <ul>
 *   <li><b>Fans out to all active super admins</b>, resolved live from the DB
 *       ({@code UserRepository.findActivePlatformRoleEmails(SUPER_ADMIN)}) and set as the event's
 *       {@code recipients} list (direct delivery; bypasses the org-scoped {@code RoleEmailMapper},
 *       which has no org context for an infra alert). Being a DB lookup, adding/removing a super
 *       admin takes effect on the next poll — no restart.</li>
 *   <li><b>Falls back</b> to the configured {@code BOOTSTRAP_SUPER_ADMIN_EMAIL}
 *       ({@code app.bootstrap-super-admin.email}) when the DB query is empty or errors, so an alert
 *       is never silently dropped. The seed placeholder {@code super_admin@certping.local} and
 *       blanks are filtered; if nothing usable remains the publish is skipped with a warning.</li>
 * </ul>
 *
 * <p>{@code notificationType} is also set as an <b>application property</b> (not just in the body),
 * for the notifier and the logs.
 *
 * <p>The {@code certNotificationsSender} bean is injected optionally so unit tests that build this
 * publisher without one skip the send instead of failing.
 */
@Slf4j
@Component
public class OperationalAlertPublisher {

    /** Non-deliverable seed default from application.yaml — means "not configured". */
    private static final String PLACEHOLDER_EMAIL = "super_admin@certping.local";

    private final ObjectMapper objectMapper;
    private final QueueAlertProperties queueAlertProperties;
    private final UserRepository userRepository;

    @Autowired(required = false)
    @Qualifier("certNotificationsSender")
    private MessageSender certNotificationsSender;

    @Value("${app.bootstrap-super-admin.email:}")
    private String fallbackSuperAdminEmail;

    @Value("${ENVIRONMENT:${spring.profiles.active:prod}}")
    private String environment;

    public OperationalAlertPublisher(ObjectMapper objectMapper,
                                     QueueAlertProperties queueAlertProperties,
                                     UserRepository userRepository) {
        this.objectMapper = objectMapper;
        this.queueAlertProperties = queueAlertProperties;
        this.userRepository = userRepository;
    }

    /**
     * Publishes one queue-depth alert (or its recovery) to all super admins.
     *
     * @param action     a {@code NotificationAction} the notifier knows (SYSTEM_DLQ_ALERT,
     *                   SYSTEM_QUEUE_DEPTH_WARNING, SYSTEM_QUEUE_ALERT_RESOLVED)
     * @param entityKey  the message queue channel
     * @param entityType QUEUE (surfaced in the email)
     * @param metric     ACTIVE or DLQ
     * @param value      current observed count
     * @param threshold  the breached threshold
     * @param severity   WARNING / CRITICAL / INFO — surfaced in the email
     */
    public void publishQueueAlert(String action, String entityKey, String entityType,
                                  String metric, long value, long threshold, String severity) {
        if (certNotificationsSender == null) {
            log.debug("[OperationalAlertPublisher] No notifications sender configured — skipping {} for {}", action, entityKey);
            return;
        }
        List<String> recipients = resolveRecipients();
        if (recipients.isEmpty()) {
            log.warn("[OperationalAlertPublisher] no usable super-admin recipients (DB SUPER_ADMIN emails empty and "
                    + "app.bootstrap-super-admin.email unset/placeholder) — skipping {} for {}", action, entityKey);
            return;
        }

        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("entity", entityKey);
        fields.put("entityType", entityType);
        fields.put("metric", metric);
        fields.put("currentValue", value);
        fields.put("threshold", threshold);
        fields.put("severity", severity);
        fields.put("environment", environment);
        fields.put("dashboardUrl", queueAlertProperties.getDashboardUrl());
        fields.put("timestamp", OffsetDateTime.now(ZoneOffset.UTC).toString());

        publish(action, fields, recipients, messageId(action, entityKey, metric), MdcIds.requestId(),
                "entity=" + entityKey + ", metric=" + metric + ", value=" + value + ", threshold=" + threshold);
    }

    private void publish(String action, Map<String, Object> fields, List<String> recipients,
                         String messageId, String requestId, String logContext) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("notificationType", "SYSTEM_EVENT");
        event.put("notificationAction", action);
        event.put("integrationType", "EMAIL");
        // Fan out to all super admins — direct recipients bypass RoleEmailMapper (no org context).
        event.put("recipients", recipients);
        event.put("source", EventSource.CERT_MANAGER.value());
        event.put("messageId", messageId);
        // Natural key for notification_records — see CertpingNotificationPublisher.
        event.put("requestId", requestId);
        event.put("correlationId", MdcIds.correlationId());
        event.put("templateFields", fields);

        String body;
        try {
            body = objectMapper.writeValueAsString(List.of(event));
        } catch (JacksonException e) {
            throw new RuntimeException("Failed to serialize operational alert notification: " + action, e);
        }

        TransportMessage message = new TransportMessage(body);
        // Deterministic id (1-min bucket) so concurrent replicas dedup at the notifier — a secondary
        // net; the queue_alert_state conditional UPDATE is the primary single-fire guard.
        message.setMessageId(messageId);
        message.getApplicationProperties().put("notificationType", "SYSTEM_EVENT");
        message.getApplicationProperties().put("source", EventSource.CERT_MANAGER.value());

        certNotificationsSender.sendMessage(message);
        OtelSpanContext.enrichNotificationPublish(
                MdcIds.requestId(),
                MdcIds.correlationId(),
                null,
                null,
                action,
                "SYSTEM_EVENT",
                message.getMessageId());
        log.info("Published operational alert: action={}, {}, recipients={}, topic={}, messageId={}",
                action, logContext, recipients.size(), "notifications", message.getMessageId());
    }

    /**
     * Resolves the alert recipients: all active platform super admins from the DB, falling back to
     * the configured {@code BOOTSTRAP_SUPER_ADMIN_EMAIL} if the query is empty or fails.
     */
    private List<String> resolveRecipients() {
        List<String> superAdmins;
        try {
            superAdmins = userRepository.findActivePlatformRoleEmails(Permissions.ROLE_SUPER_ADMIN);
        } catch (Exception e) {
            log.error("[OperationalAlertPublisher] failed to resolve SUPER_ADMIN emails from DB — "
                    + "falling back to configured address: {}", e.getMessage(), e);
            superAdmins = null;
        }
        return resolveRecipients(superAdmins, fallbackSuperAdminEmail);
    }

    /**
     * Pure recipient resolution (unit-tested): DB super-admin emails first, else the configured
     * fallback; trims, de-duplicates, and drops blanks and the seed placeholder.
     */
    static List<String> resolveRecipients(List<String> superAdminEmails, String configuredFallback) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (superAdminEmails != null) {
            for (String email : superAdminEmails) {
                if (isUsable(email)) {
                    out.add(email.trim());
                }
            }
        }
        if (out.isEmpty() && isUsable(configuredFallback)) {
            out.add(configuredFallback.trim());
        }
        return new ArrayList<>(out);
    }

    static boolean isUsable(String email) {
        if (email == null) {
            return false;
        }
        String trimmed = email.trim();
        return !trimmed.isEmpty() && !trimmed.equalsIgnoreCase(PLACEHOLDER_EMAIL);
    }

    private String messageId(String action, String entityKey, String metric) {
        long bucket = System.currentTimeMillis() / 60_000L; // 1-minute dedup bucket
        String safe = (entityKey + "-" + metric).replaceAll("[^a-zA-Z0-9]+", "-");
        return "msg-qalert-" + action.toLowerCase().replace('_', '-') + "-" + safe + "-" + bucket;
    }
}
