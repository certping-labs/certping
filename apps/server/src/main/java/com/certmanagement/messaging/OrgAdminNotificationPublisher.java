// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.MessageSender;
import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.util.MdcIds;
import com.certmanagement.util.OtelSpanContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Publishes an email to an organization's admins through the shared {@code notifications} channel, delivered
 * at most once per idempotency key: a feature paused or resumed by the platform
 * ({@code FeatureLifecycleNotifier}) and a CertPing DNS key about to expire ({@code CertPingDnsKeyExpiryNotices}).
 *
 * <p>The envelope is an {@code ACCOUNT_EVENT} addressed by role ({@code ORGANIZATION_ADMIN} of the
 * organization) with {@code deliverOnce} set: the notifier records the {@code requestId}, which is the
 * caller's idempotency key, and drops a repeat. The queue message id is derived from the same key, so a
 * retried publish is a duplicate the queue can drop too.
 */
@Slf4j
@Component
public class OrgAdminNotificationPublisher {

    static final String NOTIFICATION_TYPE = "ACCOUNT_EVENT";
    static final String ROLE = "ORGANIZATION_ADMIN";

    private final MessageSender certNotificationsSender;
    private final ObjectMapper objectMapper;

    public OrgAdminNotificationPublisher(@Qualifier("certNotificationsSender") MessageSender certNotificationsSender,
                                         ObjectMapper objectMapper) {
        this.certNotificationsSender = certNotificationsSender;
        this.objectMapper = objectMapper;
    }

    /**
     * Publishes {@code action} to the admins of {@code organizationId}, once per {@code idempotencyKey}.
     *
     * @throws RuntimeException when the message cannot be serialized or sent; the caller retries later
     */
    public void publishOnceToOrgAdmins(String action, String organizationId, String source,
                                       Map<String, Object> templateFields, String idempotencyKey) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("notificationType", NOTIFICATION_TYPE);
        event.put("notificationAction", action);
        event.put("integrationType", "EMAIL");
        event.put("organizationId", organizationId);
        event.put("source", source);
        event.put("templateFields", templateFields == null ? Map.of() : new LinkedHashMap<>(templateFields));
        event.put("roles", List.of(ROLE));
        // Natural key for notification_records: the notifier delivers each key once.
        event.put("requestId", idempotencyKey);
        event.put("correlationId", MdcIds.correlationId());
        event.put("deliverOnce", true);

        String body;
        try {
            body = objectMapper.writeValueAsString(List.of(event));
        } catch (JacksonException e) {
            throw new RuntimeException("Failed to serialize notification payload for action=" + action, e);
        }

        TransportMessage message = new TransportMessage(body);
        message.setMessageId(messageId(action, idempotencyKey));
        message.getApplicationProperties().put("notificationType", NOTIFICATION_TYPE);
        message.getApplicationProperties().put("source", source);
        if (organizationId != null) {
            message.getApplicationProperties().put("organizationId", organizationId);
        }

        certNotificationsSender.sendMessage(message);
        OtelSpanContext.enrichNotificationPublish(idempotencyKey, MdcIds.correlationId(), organizationId, null,
                action, NOTIFICATION_TYPE, message.getMessageId());
        log.info("Published organization admin notification: action={}, organizationId={}, messageId={}",
                action, organizationId, message.getMessageId());
    }

    /** A stable id for one action and key: {@code org-} and the first 12 bytes of their SHA-256, in hex. */
    static String messageId(String action, String idempotencyKey) {
        String fingerprint = (action == null ? "" : action) + "|" + (idempotencyKey == null ? "" : idempotencyKey);
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(fingerprint.getBytes(StandardCharsets.UTF_8));
            StringBuilder id = new StringBuilder("org-");
            for (int i = 0; i < 12; i++) {
                int value = hash[i] & 0xFF;
                id.append(Character.forDigit((value >>> 4) & 0xF, 16)).append(Character.forDigit(value & 0xF, 16));
            }
            return id.toString();
        } catch (NoSuchAlgorithmException e) {
            return "org-" + Long.toUnsignedString(fingerprint.hashCode(), 16);
        }
    }
}
