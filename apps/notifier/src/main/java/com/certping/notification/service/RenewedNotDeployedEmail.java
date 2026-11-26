// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.model.NotificationEvent;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Map;

/**
 * Subject and model values for CERT_RENEWED_NOT_DEPLOYED, which the server's CertResponseProcessor
 * sends after a renewal when automatic deployment is turned off for the organization;
 * DeliverOncePolicy makes it deliver-once under its {@code requestId}. Its template fields are
 * {@code domain}, {@code validTo} (the new certificate's), {@code previousValidTo} (when the
 * certificate in use expires, empty when unknown), {@code reason}, {@code previousCertificateXref},
 * {@code certificateXref} and {@code requestId}.
 *
 * <p>What reaches the template: every template field HTML-escaped with its braces encoded
 * (EmailText.escape), the raw {@code templateFields} map dropped, dates as words, and the
 * certificate page built from the dashboard address and the path-encoded certificate reference.
 */
final class RenewedNotDeployedEmail {

    /** The certificate's page in the dashboard; "Url" keeps it under the providers' link sanitizer. */
    static final String CERTIFICATE_PAGE_URL = "certificatePageUrl";
    /** The domain for a sentence: "your domain" when the event names none. */
    static final String DOMAIN_PHRASE = "domainPhrase";
    /** " on 4 Jan 2027" when the current certificate's expiry is known, else empty. */
    static final String CURRENT_EXPIRY_PHRASE = "currentExpiryPhrase";

    private static final String SUBJECT_PREFIX = "CertPing - Certificate for ";
    private static final String SUBJECT_SUFFIX = " renewed — deploy it to keep it in use";
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    private RenewedNotDeployedEmail() {
    }

    static boolean handles(NotificationAction action) {
        return action == NotificationAction.CERT_RENEWED_NOT_DEPLOYED;
    }

    /** The domain is cut short when it must be, so the call to deploy always survives. */
    static String subject(NotificationEvent event) {
        String domain = EmailText.field(event, "domain");
        return EmailText.subject(SUBJECT_PREFIX, domain.isEmpty() ? "your domain" : domain, SUBJECT_SUFFIX);
    }

    /** Called once the model holds the flattened template fields and the envelope values. */
    static void prepareModel(NotificationEvent event, Map<String, Object> model) {
        Map<String, Object> fields = event.getTemplateFields() == null ? Map.of() : event.getTemplateFields();
        String certificatePage = EmailText.certificatePage(model.get("frontendBaseUrl"), fields.get("certificateXref"));
        EmailText.escapeTemplateFields(event, model);
        model.put(CERTIFICATE_PAGE_URL, certificatePage);
        String domain = EmailText.trimmed(model.get("domain"));
        model.put("domain", orDash(domain));
        model.put(DOMAIN_PHRASE, domain.isEmpty() ? "your domain" : domain);
        model.put("validTo", orDash(dateWords(fields.get("validTo"))));
        model.put("certificateXref", orDash(EmailText.trimmed(model.get("certificateXref"))));
        model.put("previousCertificateXref", orDash(EmailText.trimmed(model.get("previousCertificateXref"))));
        String currentExpiry = dateWords(fields.get("previousValidTo"));
        model.put(CURRENT_EXPIRY_PHRASE, currentExpiry.isEmpty() ? "" : " on <strong>" + currentExpiry + "</strong>");
    }

    /** An ISO-8601 instant or date as "4 Jan 2027"; anything else is shown as sent, escaped. */
    private static String dateWords(Object value) {
        String text = EmailText.trimmed(value);
        if (text.isEmpty()) {
            return "";
        }
        try {
            return DATE_FORMAT.format(OffsetDateTime.parse(text));
        } catch (DateTimeParseException notAnInstant) {
            try {
                return DATE_FORMAT.format(LocalDate.parse(text).atStartOfDay(ZoneOffset.UTC));
            } catch (DateTimeParseException notADate) {
                return EmailText.escape(text);
            }
        }
    }

    private static String orDash(String value) {
        return value.isEmpty() ? "&ndash;" : value;
    }
}
