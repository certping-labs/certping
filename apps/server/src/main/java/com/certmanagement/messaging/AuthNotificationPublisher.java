// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.enums.EventSource;
import com.certmanagement.util.MdcIds;
import com.certmanagement.util.OtelSpanContext;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Publishes account notification events (password reset and change)
 * to the same {@code notifications} channel that {@link CertpingNotificationPublisher} uses.
 *
 * <p><b>Why a separate publisher:</b> the existing cert publisher resolves recipients by role
 * ("send to all ORGANIZATION_ADMINs of this org") — perfect for cert lifecycle, wrong for auth.
 * Auth emails target a single person (the user who requested the reset). This publisher
 * adds {@code recipientEmail} and {@code recipientUserId} to the event so the notifier
 * can deliver to that person directly.</p>
 *
 * <p><b>Contract with the notifier:</b> action strings come from
 * {@link AuthNotificationActions} and must each have a corresponding {@code NotificationAction}
 * enum value + Thymeleaf template ({@code reset-password.html}, etc.) on the other
 * side (apps/notifier). Adding an action means adding both.</p>
 */
@Slf4j
@Component
public class AuthNotificationPublisher {

    private final MessageSender certNotificationsSender;
    private final ObjectMapper objectMapper;

    public AuthNotificationPublisher(
            @Qualifier("certNotificationsSender") MessageSender certNotificationsSender,
            ObjectMapper objectMapper) {
        this.certNotificationsSender = certNotificationsSender;
        this.objectMapper = objectMapper;
    }

    /**
     * Publish an auth-domain notification.
     *
     * @param action          one of {@link AuthNotificationActions}
     * @param recipientEmail  exact email to deliver to (NOT role-resolved)
     * @param recipientUserId user id, included for audit / tracing
     * @param organizationId  org of the recipient
     * @param templateFields  template variables — {@code resetLink}, {@code username}, etc.
     * @param requestId       optional request id used to derive a stable message id
     *
     * <p>Send failures propagate as {@link RuntimeException} so callers can decide whether
     * the surrounding transaction should still commit.</p>
     */
    public void publish(String action,
                        String recipientEmail,
                        Integer recipientUserId,
                        Long organizationId,
                        Map<String, Object> templateFields,
                        String requestId) {
        publishEvent(action, recipientEmail, recipientUserId, organizationId, templateFields, requestId);
    }

    private void publishEvent(String action,
                              String recipientEmail,
                              Integer recipientUserId,
                              Long organizationId,
                              Map<String, Object> templateFields,
                              String requestId) {

        Map<String, Object> fields = new LinkedHashMap<>();
        if (templateFields != null) {
            fields.putAll(templateFields);
        }

        String messageId = stableMessageId(action, recipientEmail, requestId);

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("notificationType",   "ACCOUNT_EVENT");
        event.put("notificationAction", action);
        event.put("integrationType",    "EMAIL");
        event.put("organizationId",     organizationId != null ? organizationId.toString() : null);
        // Direct-recipient fields. Field names match the notifier's NotificationEvent model
        // ("email", "userId" — not "recipientEmail"/"recipientUserId", which are unknown there and
        // would cause Jackson UnrecognizedPropertyException → DLQ).
        // The notifier may use these directly for auth-domain actions, or fall back to role
        // resolution via the "roles" field below.
        event.put("email",              recipientEmail);
        event.put("userId",             recipientUserId);
        // Role-based recipient resolution fallback — same convention as CertpingNotificationPublisher.
        event.put("roles", List.of("ORGANIZATION_ADMIN"));
        event.put("source",             EventSource.CERT_MANAGER.value());
        event.put("messageId",          messageId);
        // Natural key for notification_records — see CertpingNotificationPublisher for the rationale.
        event.put("requestId",          requestId == null || requestId.isBlank() ? messageId : requestId);
        event.put("correlationId",      MdcIds.correlationId());
        event.put("templateFields",     fields);

        String body;
        try {
            body = objectMapper.writeValueAsString(List.of(event));
        } catch (JacksonException e) {
            throw new RuntimeException("Failed to serialize auth notification payload for action=" + action, e);
        }

        TransportMessage message = new TransportMessage(body);
        message.setMessageId(messageId);
        message.getApplicationProperties().put("notificationType", "ACCOUNT_EVENT");
        message.getApplicationProperties().put("source", EventSource.CERT_MANAGER.value());
        if (organizationId != null) {
            message.getApplicationProperties().put("organizationId", organizationId.toString());
        }

        certNotificationsSender.sendMessage(message);
        OtelSpanContext.enrichNotificationPublish(
                requestId,
                null,
                organizationId != null ? organizationId.toString() : null,
                null,
                action,
                "ACCOUNT_EVENT",
                message.getMessageId());
        log.info("Published auth notification: action={}, recipientUserId={}, organizationId={}, messageId={}",
                action, recipientUserId, organizationId, message.getMessageId());
    }

    private String stableMessageId(String action, String recipientEmail, String requestId) {
        String seed = (requestId == null || requestId.isBlank())
                ? UUID.randomUUID().toString()
                : requestId;
        String fingerprint = String.join("|",
                action != null ? action : "",
                recipientEmail != null ? recipientEmail : "",
                seed);
        return "auth-" + shortDigest(fingerprint);
    }

    private String shortDigest(String fingerprint) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fingerprint.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(24);
            for (int i = 0; i < 12; i++) {
                int v = hash[i] & 0xFF;
                sb.append(Character.forDigit((v >>> 4) & 0xF, 16));
                sb.append(Character.forDigit(v & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            return Long.toUnsignedString(fingerprint.hashCode(), 16);
        }
    }
}
