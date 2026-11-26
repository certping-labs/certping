// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * What of an event's template fields may be stored. A password reset or account verification link
 * is a bearer secret: whoever reads it can take the account, so it is never written to
 * {@code notification_records.payload_json} or anywhere else an API can return. The email itself is
 * rendered from the original event and still carries the real link.
 *
 * <p>Redacted, at any depth: a field whose name contains token, secret or password; for an account
 * or password email, any field whose name contains link or url; and any string value that holds a
 * {@code token=} query parameter or looks like a JWT.
 */
public final class SecretFields {

    public static final String REDACTED = "[redacted]";

    /** Account and password emails: every link in them is a credential or leads to one. */
    static final Set<NotificationAction> AUTH_ACTIONS = EnumSet.of(
            NotificationAction.PASSWORD_CHANGE_SUCCESS, NotificationAction.RESET_PASSWORD);

    private static final List<String> SECRET_NAME_PARTS = List.of("token", "secret", "password");
    private static final List<String> AUTH_LINK_NAME_PARTS = List.of("link", "url");
    private static final Pattern TOKEN_PARAMETER = Pattern.compile("(?i)[?&#;]([a-z_]*token|code|key|signature|sig)=");
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]+");

    private SecretFields() {
    }

    /** True when the stored copy of this event must leave out {@code value} under {@code name}. */
    static boolean isSecret(NotificationAction action, String name, Object value) {
        String lower = name == null ? "" : name.toLowerCase(Locale.ROOT);
        if (SECRET_NAME_PARTS.stream().anyMatch(lower::contains)) {
            return true;
        }
        if (action != null && AUTH_ACTIONS.contains(action) && AUTH_LINK_NAME_PARTS.stream().anyMatch(lower::contains)) {
            return true;
        }
        return value instanceof CharSequence text && holdsSecret(text.toString());
    }

    /** A string carrying a token query parameter or a JWT. */
    public static boolean holdsSecret(String value) {
        return value != null && (TOKEN_PARAMETER.matcher(value).find() || JWT.matcher(value).find());
    }

    /**
     * A copy of {@code fields} with every secret replaced by {@link #REDACTED}; the same map when
     * nothing in it is secret, so a caller can tell nothing changed.
     */
    public static Map<String, Object> redact(NotificationAction action, Map<String, Object> fields) {
        if (fields == null || fields.isEmpty()) {
            return fields;
        }
        Map<String, Object> copy = null;
        for (Map.Entry<String, Object> entry : fields.entrySet()) {
            Object value = entry.getValue();
            Object stored = isSecret(action, entry.getKey(), value) && value != null ? REDACTED : redactValue(action, value);
            if (stored != value) {
                if (copy == null) {
                    copy = new LinkedHashMap<>(fields);
                }
                copy.put(entry.getKey(), stored);
            }
        }
        return copy == null ? fields : copy;
    }

    @SuppressWarnings("unchecked")
    private static Object redactValue(NotificationAction action, Object value) {
        if (value instanceof Map<?, ?> map) {
            return redact(action, (Map<String, Object>) map);
        }
        if (value instanceof List<?> list) {
            List<Object> copy = null;
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                Object stored = item instanceof CharSequence text && holdsSecret(text.toString())
                        ? REDACTED : redactValue(action, item);
                if (stored != item) {
                    if (copy == null) {
                        copy = new ArrayList<>(list);
                    }
                    copy.set(i, stored);
                }
            }
            return copy == null ? list : copy;
        }
        return value;
    }
}
