// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.enums.EventSource;
import com.certmanagement.integration.IntegrationNotificationClient;
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

/**
 * Publishes certificate lifecycle notification events to the notifications queue
 * so that the notifier can route and send emails to organization admins.
 *
 * <p>Message format: a JSON array of one NotificationEvent-compatible object,
 * matching the List&lt;NotificationEvent&gt; that the notifier deserialises from the message
 * body.</p>
 *
 * <p>The {@code action} string passed to {@link #publish} must match a
 * {@code NotificationAction} enum value in the notifier exactly, because
 * the notifier resolves the email template as:
 * {@code notificationAction.name().toLowerCase().replace("_", "-") + ".html"}</p>
 *
 * <p>Supported actions and their resolved templates:</p>
 * <ul>
 *   <li>CERT_ISSUANCE_SUCCESS   → cert-issuance-success.html</li>
 *   <li>CERT_ISSUANCE_FAILED    → cert-issuance-failed.html</li>
 *   <li>CERT_MANUAL_TXT_READY   → cert-manual-txt-ready.html</li>
 *   <li>CERT_RENEWAL_SUCCESS    → cert-renewal-success.html</li>
 *   <li>CERT_RENEWAL_FAILED     → cert-renewal-failed.html</li>
 *   <li>CERT_DEPLOYMENT_SUCCESS → cert-deployment-success.html</li>
 *   <li>CERT_DEPLOYMENT_FAILED  → cert-deployment-failed.html</li>
 * </ul>
 *
 * <p>Recipient resolution is role-based: the event carries {@code roles: ["ORGANIZATION_ADMIN"]},
 * and the notifier's RoleEmailMapper resolves that to the active organization-admin emails
 * for the given organizationId. No email address is hardcoded or passed from the server.</p>
 */
@Slf4j
@Component
public class CertpingNotificationPublisher implements NotificationPublisher {

    private final MessageSender certNotificationsSender;
    private final ObjectMapper objectMapper;
    private final IntegrationNotificationClient integrationNotificationClient;

    public CertpingNotificationPublisher(
            @Qualifier("certNotificationsSender") MessageSender certNotificationsSender,
            ObjectMapper objectMapper,
            IntegrationNotificationClient integrationNotificationClient) {
        this.certNotificationsSender        = certNotificationsSender;
        this.objectMapper                   = objectMapper;
        this.integrationNotificationClient  = integrationNotificationClient;
    }

    /**
     * Publishes a cert lifecycle notification event.
     *
     * <p>Exceptions are <em>intentionally not swallowed</em> here — {@code JsonProcessingException}
     * is wrapped and rethrown as {@code RuntimeException}; send failures propagate naturally.
     * The caller ({@link CertResponseProcessor}) catches these <em>after</em> completing the
     * inbound message, so a notification failure never causes message re-delivery.
     *
     * @param action          must match a NotificationAction enum value in the notifier
     *                        (e.g. CERT_ISSUANCE_SUCCESS, CERT_RENEWAL_FAILED)
     * @param organizationId        organization identifier — used for role-to-email resolution
     * @param certificateXref cert cross-reference ID (added into templateFields)
     * @param details         template variables: domain, validTo, validFrom, errorCode, etc.
     */
    public void publish(String action, String organizationId, String certificateXref,
                        Map<String, Object> details) {
        // Build templateFields: merge details + certificateXref
        Map<String, Object> templateFields = new LinkedHashMap<>();
        if (details != null) {
            templateFields.putAll(details);
        }
        if (certificateXref != null) {
            templateFields.put("certificateXref", certificateXref);
        }
        String requestId = asString(templateFields.get("requestId"));
        String messageId = stableMessageId(action, organizationId, certificateXref, requestId);

        // Build a NotificationEvent-compatible map
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("notificationType",   "ACCOUNT_EVENT");       // routes to the notifier's account-event handling
        event.put("notificationAction", action);                 // must match NotificationAction enum in the notifier
        event.put("integrationType",    "EMAIL");
        event.put("organizationId",           organizationId);
        event.put("roles",              List.of("ORGANIZATION_ADMIN")); // RoleEmailMapper resolves recipients
        event.put("source",             EventSource.CERT_MANAGER.value());
        event.put("messageId",          messageId);
        // Stable identity used by the notifier as the notification_records
        // natural key (find-or-insert on every retry, so one row per logical
        // notification instead of one per attempt). Falls back to messageId
        // if the publisher didn't include a requestId in templateFields.
        event.put("requestId",          requestId == null || requestId.isBlank() ? messageId : requestId);
        event.put("correlationId",      MdcIds.correlationId());
        event.put("templateFields",     templateFields);

        // The notifier deserialises as List<NotificationEvent>
        String body;
        try {
            body = objectMapper.writeValueAsString(List.of(event));
        } catch (JacksonException e) {
            // Wrap checked exception — propagates to CertResponseProcessor post-ACK catch block
            throw new RuntimeException("Failed to serialize notification payload for action=" + action, e);
        }

        TransportMessage message = new TransportMessage(body);
        // Stable per-(action, org, xref, requestId) id — used by the notifier for
        // application-level dedup AND by the queue's duplicate detection on message id.
        // Setting it explicitly is intentional here, because dedup requires a deterministic value.
        message.setMessageId(messageId);
        message.getApplicationProperties().put("notificationType", "ACCOUNT_EVENT");
        message.getApplicationProperties().put("source",           EventSource.CERT_MANAGER.value());
        message.getApplicationProperties().put("organizationId",         organizationId);

        certNotificationsSender.sendMessage(message);
        OtelSpanContext.enrichNotificationPublish(
                requestId,
                MdcIds.correlationId(),
                organizationId,
                certificateXref,
                action,
                "ACCOUNT_EVENT",
                message.getMessageId());
        // Log topic + messageType
        // MessageId as structured fields. Never push this messageId into MDC — [msg=...] is
        // reserved for the message currently being consumed, never one we're publishing.
        log.info("Published notification: messageType=ACCOUNT_EVENT, topic={}, action={}, organizationId={}, xref={}, messageId={}",
                "notifications", action, organizationId, certificateXref, message.getMessageId());

        // Deliver to Teams + Slack integrations (dispatch — never fails the caller).
        integrationNotificationClient.dispatch(organizationId, action, certificateXref, templateFields);
    }

    private String stableMessageId(String action, String organizationId, String certificateXref, String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return "msg-" + System.nanoTime();
        }
        String fingerprint = String.join("|",
                action != null ? action : "",
                organizationId != null ? organizationId : "",
                certificateXref != null ? certificateXref : "",
                requestId);
        return "msg-" + shortDigest(fingerprint);
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

    private String asString(Object value) {
        return value != null ? value.toString() : null;
    }
}
