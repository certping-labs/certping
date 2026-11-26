// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.model.NotificationEvent;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Map;

/**
 * Subject and model values for CERTPING_DNS_KEY_EXPIRING, which the server sends 30 days and again 7 days before
 * a CertPing DNS key expires, since certificates validated through it stop renewing then. Its template fields are
 * {@code credentialName}, {@code tokenPrefix}, {@code expiresAt} (an ISO-8601 instant), {@code leadDays} (30 or 7)
 * and {@code idempotencyKey}; DeliverOncePolicy makes it deliver-once under the key. Every template field reaches
 * the template escaped (EmailText.escape).
 *
 * <p>Without the credential name the sentences say "your CertPing DNS key", and without a date they leave it out.
 */
final class CertPingDnsKeyExpiringEmail {

    static final String EYEBROW = "dnsKeyEyebrow";
    static final String HEADING = "dnsKeyHeading";
    static final String PREHEADER = "dnsKeyPreheader";
    static final String LEAD = "dnsKeyLead";
    static final String IMPACT = "dnsKeyImpact";
    static final String ACTION = "dnsKeyAction";

    private static final String REMINDER_LEAD_DAYS = "7";
    private static final String NO_NAME = "your CertPing DNS key";
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    private CertPingDnsKeyExpiringEmail() {
    }

    static boolean handles(NotificationAction action) {
        return action == NotificationAction.CERTPING_DNS_KEY_EXPIRING;
    }

    /** The name is cut short when it must be, so the date always survives. */
    static String subject(NotificationEvent event) {
        String name = EmailText.field(event, "credentialName");
        String expiresOn = dateWords(EmailText.field(event, "expiresAt"));
        return EmailText.subject(isReminder(event) ? "CertPing - Reminder: " : "CertPing - ",
                name.isEmpty() ? NO_NAME : "DNS key " + name,
                expiresOn.isEmpty() ? " expires soon" : " expires on " + expiresOn);
    }

    /** Called once the model holds the flattened template fields and the envelope values. */
    static void prepareModel(NotificationEvent event, Map<String, Object> model) {
        String name = EmailText.escape(EmailText.field(event, "credentialName"));
        String prefix = EmailText.escape(EmailText.field(event, "tokenPrefix"));
        String expiresOn = EmailText.escape(dateWords(EmailText.field(event, "expiresAt")));

        EmailText.escapeTemplateFields(event, model);
        model.put(EYEBROW, isReminder(event) ? "Reminder" : "DNS key expiring");
        model.put(HEADING, isReminder(event) ? "Reminder: your CertPing DNS key expires soon"
                : "Your CertPing DNS key expires soon");
        model.put(PREHEADER, (name.isEmpty() ? "Your CertPing DNS key" : "The CertPing DNS key " + name)
                + (expiresOn.isEmpty() ? " expires soon." : " expires on " + expiresOn + "."));
        model.put(LEAD, lead(name, prefix, expiresOn));
        model.put(IMPACT, "After that, certificates validated through it stop renewing automatically. They stay valid "
                + "until they expire.");
        model.put(ACTION, "Create a new CertPing DNS key for this domain in CertPing"
                + (expiresOn.isEmpty() ? "" : " before " + strong(expiresOn) + " (UTC)")
                + ". Renewals continue as soon as the new key is saved.");
    }

    /** Every value is escaped already. */
    private static String lead(String name, String prefix, String expiresOn) {
        String key = name.isEmpty() ? "Your CertPing DNS key" : "The CertPing DNS key " + strong(name);
        String expires = expiresOn.isEmpty() ? " expires soon." : " expires on " + strong(expiresOn) + " (UTC).";
        return key + expires + (prefix.isEmpty() ? "" : " It is the key starting " + strong(prefix) + ".");
    }

    private static boolean isReminder(NotificationEvent event) {
        return REMINDER_LEAD_DAYS.equals(EmailText.field(event, "leadDays"));
    }

    /** An ISO-8601 instant as its UTC day, "10 Nov 2026"; anything else as sent. */
    private static String dateWords(String instant) {
        if (instant.isEmpty()) {
            return "";
        }
        try {
            return DATE_FORMAT.format(Instant.parse(instant));
        } catch (DateTimeParseException notAnInstant) {
            return instant;
        }
    }

    private static String strong(String escaped) {
        return "<strong>" + escaped + "</strong>";
    }
}
