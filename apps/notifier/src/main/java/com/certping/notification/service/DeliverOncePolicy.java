// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.interceptor.RequestContextInterceptor;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.utils.MessageIds;
import com.certping.notification.utils.RequestContextLogger;
import org.slf4j.Logger;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Makes the emails the server may publish more than once for one change deliver-once, so each
 * admin gets one email per notification however many pods, redeliveries or retries carry it:
 * FEATURE_PAUSED, FEATURE_RESUMED, CERT_RENEWED_NOT_DEPLOYED and CERTPING_DNS_KEY_EXPIRING.
 *
 * <p>A defensive fallback alongside the producer's own {@code deliverOnce} flag: the server sets it
 * on the FEATURE_* events, but not on CERT_RENEWED_NOT_DEPLOYED, and an older publisher may set it on
 * neither. The listener applies it once, as it reads a message body, so processing, retry copies,
 * dead-lettering and undelivered records all see the same key and flag.
 */
final class DeliverOncePolicy {

    private static final Set<NotificationAction> ACTIONS = EnumSet.of(NotificationAction.FEATURE_PAUSED,
            NotificationAction.FEATURE_RESUMED, NotificationAction.CERT_RENEWED_NOT_DEPLOYED,
            NotificationAction.CERTPING_DNS_KEY_EXPIRING);

    private static final String PUBLISHER_KEY_FIELD = "idempotencyKey";
    private static final String REQUEST_ID_FIELD = "requestId";

    private DeliverOncePolicy() {
    }

    static boolean covers(NotificationAction action) {
        return ACTIONS.contains(action);
    }

    /**
     * Makes a covered event deliver-once under the first key it has, in order: an explicit
     * {@code notificationKey}; a valid {@code templateFields.idempotencyKey}; a valid envelope
     * {@code requestId}; a valid {@code templateFields.requestId}. An event with none is delivered as
     * usual and logged. Idempotent, so a retried body is unchanged.
     */
    static void apply(NotificationEvent event) {
        if (event == null || !covers(event.getNotificationAction())) {
            return;
        }
        if (isBlank(event.getNotificationKey())) {
            String key = firstValid(templateField(event, PUBLISHER_KEY_FIELD), event.getRequestId(),
                    templateField(event, REQUEST_ID_FIELD));
            if (key == null) {
                contextLogger().warn("{} event has no valid idempotency key ({}); delivering it without deliver-once",
                        event.getNotificationAction().name(), MessageIds.loggable(event.idempotencyKey()));
                return;
            }
            if (!key.equals(event.getRequestId())) {
                event.setNotificationKey(key);
            }
        }
        event.setDeliverOnce(true);
    }

    private static String firstValid(Object... candidates) {
        for (Object candidate : candidates) {
            String valid = MessageIds.valid(candidate);
            if (valid != null) {
                return valid;
            }
        }
        return null;
    }

    private static Object templateField(NotificationEvent event, String name) {
        Map<String, Object> fields = event.getTemplateFields();
        return fields == null ? null : fields.get(name);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static Logger contextLogger() {
        return RequestContextLogger.getLogger(DeliverOncePolicy.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
