// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.model.NotificationEvent;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Subjects and model values for FEATURE_PAUSED and FEATURE_RESUMED, which the server sends to an
 * organization's admins when CertPing turns a feature off or back on for it; DeliverOncePolicy makes
 * them deliver-once.
 *
 * <p>What reaches the template: every template field HTML-escaped with its braces encoded
 * (EmailText.escape), the raw {@code templateFields} map dropped, and the details panel pre-rendered
 * from those escaped values. An event without a field still renders: the feature is then
 * "A CertPing feature", the organization "your organization", a row nothing fills is left out, and a
 * panel with no row at all is left out with it. The server sends FEATURE_RESUMED after every
 * FEATURE_PAUSED, even when no record resumed; that email then has no items sentence at all.
 */
final class FeatureLifecycleEmail {

    /** The feature's name for the copy, escaped, or {@link #UNNAMED_FEATURE}. */
    static final String FEATURE_NAME = "featureName";
    /**
     * The pre-rendered row holding the sentence before the details, which points at the record rows or
     * stands alone without any; empty for FEATURE_RESUMED without records, so no padded blank row remains.
     */
    static final String ITEMS_INTRO_ROW = "itemsIntroRow";
    /**
     * The pre-rendered details panel, empty when it would have no row. Neither "link" nor "url" may
     * appear in a key holding HTML: the SMTP provider replaces such a value with "#".
     */
    static final String DETAILS_PANEL = "detailsPanel";

    static final String UNNAMED_FEATURE = "A CertPing feature";

    private static final Set<NotificationAction> ACTIONS =
            EnumSet.of(NotificationAction.FEATURE_PAUSED, NotificationAction.FEATURE_RESUMED);

    private static final String ITEMS_FIELD = "items";
    private static final String ORGANIZATION_NAME_FIELD = "organizationName";
    private static final String OCCURRED_AT_FIELD = "occurredAt";

    private static final DateTimeFormatter OCCURRED_AT_FORMAT =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    private FeatureLifecycleEmail() {
    }

    static boolean handles(NotificationAction action) {
        return ACTIONS.contains(action);
    }

    static String subject(NotificationEvent event) {
        String feature = EmailText.field(event, FEATURE_NAME);
        String named = feature.isEmpty() ? UNNAMED_FEATURE : feature;
        return EmailText.subject("CertPing - " + switch (event.getNotificationAction()) {
            case FEATURE_PAUSED -> named + " is paused for "
                    + orDefault(EmailText.field(event, ORGANIZATION_NAME_FIELD), "your organization");
            case FEATURE_RESUMED -> named + " is available again";
            default -> throw new IllegalArgumentException(event.getNotificationAction().name());
        });
    }

    /** Called once the model holds the flattened template fields and the envelope values. */
    static void prepareModel(NotificationEvent event, Map<String, Object> model) {
        Map<String, Object> fields = event.getTemplateFields() == null ? Map.of() : event.getTemplateFields();
        EmailText.escapeTemplateFields(event, model);
        String feature = EmailText.trimmed(model.get(FEATURE_NAME));
        model.put(FEATURE_NAME, feature.isEmpty() ? UNNAMED_FEATURE : feature);
        String itemRows = EmailText.itemRows(fields.get(ITEMS_FIELD));
        model.put(ITEMS_INTRO_ROW, itemsIntroRow(event.getNotificationAction(), !itemRows.isEmpty()));
        String featureRow = feature.isEmpty() ? "" : EmailText.detailRow("Feature", feature);
        String occurredAt = occurredAtWords(fields.get(OCCURRED_AT_FIELD));
        String occurredAtRow = occurredAt.isEmpty() ? "" : EmailText.detailRow("When", occurredAt);
        model.put(DETAILS_PANEL, EmailText.detailsPanel(featureRow + itemRows + occurredAtRow));
    }

    /** The sentences hold no publisher value, so nothing in the row needs escaping. */
    private static String itemsIntroRow(NotificationAction action, boolean hasItems) {
        if (action == NotificationAction.FEATURE_PAUSED) {
            return EmailText.copyRow(
                    hasItems ? "Your data is kept, including the records below." : "Your data is kept.");
        }
        return hasItems ? EmailText.copyRow("The records below have resumed automatically.") : "";
    }

    /** The server sends an ISO-8601 instant; the email shows it in UTC, or as sent, escaped, when unparseable. */
    private static String occurredAtWords(Object value) {
        String text = EmailText.trimmed(value);
        if (text.isEmpty()) {
            return "";
        }
        try {
            return OCCURRED_AT_FORMAT.format(OffsetDateTime.parse(text));
        } catch (DateTimeParseException unparseable) {
            return EmailText.escape(text);
        }
    }

    private static String orDefault(String value, String fallback) {
        return value.isEmpty() ? fallback : value;
    }
}
