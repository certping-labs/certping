// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.model.NotificationEvent;

import java.util.Map;

/**
 * Subject and model values for CERT_REVOCATION_FAILED, which the server's CertResponseProcessor sends
 * when the agent answers a revocation command with an error. Its template fields are {@code domain},
 * {@code errorCode} (the agent's code, never its detail), {@code requestId} and {@code certificateXref}.
 *
 * <p>What reaches the template: every template field HTML-escaped with its braces encoded
 * (EmailText.escape), the raw {@code templateFields} map dropped, a dash for a reference not sent, and
 * the certificate page built from the dashboard address and the path-encoded certificate reference.
 */
final class RevocationFailedEmail {

    /** The certificate's page in the dashboard; "Url" keeps it under the providers' link sanitizer. */
    static final String CERTIFICATE_PAGE_URL = "certificatePageUrl";
    /** The domain for a sentence: "your domain" when the event names none. */
    static final String DOMAIN_PHRASE = "domainPhrase";

    private static final String SUBJECT_PREFIX = "CertPing - Revoking the certificate for ";
    private static final String SUBJECT_SUFFIX = " failed";

    private RevocationFailedEmail() {
    }

    static boolean handles(NotificationAction action) {
        return action == NotificationAction.CERT_REVOCATION_FAILED;
    }

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
        model.put(DOMAIN_PHRASE, domain.isEmpty() ? "your domain" : domain);
        for (String field : new String[] {"domain", "errorCode", "certificateXref", "requestId"}) {
            String value = EmailText.trimmed(model.get(field));
            model.put(field, value.isEmpty() ? "&ndash;" : value);
        }
    }
}
