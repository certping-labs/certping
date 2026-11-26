// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.model.NotificationEvent;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Text helpers for the emails whose every publisher value is escaped before it reaches a template
 * (FeatureLifecycleEmail, RenewedNotDeployedEmail, RevocationFailedEmail, CertPingDnsKeyExpiringEmail).
 *
 * <p>Both providers fill a template one model entry at a time, in no fixed order, so a value holding
 * {@code {{otherKey}}} could be filled in by a later entry. {@link #escape} therefore encodes braces as
 * well as HTML, and a value it returns can never form a placeholder.
 */
final class EmailText {

    /** The subject before the environment label; a longer one is cut short with an ellipsis. */
    static final int MAX_SUBJECT_LENGTH = 150;

    /** One label/value row of a details panel; both arguments must already be escaped. */
    static final String DETAIL_ROW_HTML = "<tr><td class=\"cp-slate cp-rule cp-label-cell\" width=\"168\" "
            + "valign=\"top\" style=\"width:168px;font-family:'Plus Jakarta Sans',-apple-system,BlinkMacSystemFont,"
            + "'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:20px;font-weight:400;"
            + "color:#52627A;padding:11px 16px 11px 0;border-top:1px solid #E4E9F2;mso-line-height-rule:exactly;\">"
            + "%s</td>"
            + "<td class=\"cp-ink cp-rule cp-value-cell\" valign=\"top\" style=\"font-size:13px;line-height:20px;"
            + "font-family:'Plus Jakarta Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,"
            + "sans-serif;font-weight:700;color:#0B132B;padding:11px 0;border-top:1px solid #E4E9F2;"
            + "mso-line-height-rule:exactly;\">%s</td></tr>";

    /** The template's details panel around its rows, as its other panels are marked up. */
    private static final String DETAILS_PANEL_START = "<tr><td style=\"padding:0 0 28px 0;\">"
            + "<table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" "
            + "class=\"cp-evidence\" bgcolor=\"#F7F9FC\" style=\"border-collapse:separate;background-color:#F7F9FC;"
            + "border:1px solid #CBD5E1;border-radius:6px;\">"
            + "<tr><td class=\"cp-inset\" style=\"padding:15px 20px 0 20px;\"><div class=\"cp-slate\" "
            + "style=\"font-family:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono','Courier New',"
            + "monospace;font-size:10px;line-height:14px;font-weight:500;letter-spacing:1.1px;text-transform:uppercase;"
            + "color:#52627A;padding:0 0 4px 0;mso-line-height-rule:exactly;\">Details</div></td></tr>"
            + "<tr><td class=\"cp-inset\" style=\"padding:0 20px 4px 20px;\">"
            + "<table role=\"presentation\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" "
            + "style=\"border-collapse:collapse;\">";
    private static final String DETAILS_PANEL_END = "</table></td></tr></table></td></tr>";

    /** The template's body-copy row, as its other sentences are marked up. */
    private static final String COPY_ROW_HTML = "<tr><td class=\"cp-slate\" style=\"font-family:'Plus Jakarta Sans',"
            + "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;"
            + "line-height:25px;font-weight:400;color:#52627A;padding:0 0 14px 0;mso-line-height-rule:exactly;\">"
            + "%s</td></tr>";

    /** A runaway list would make an unreadable email; producers send one entry per kind of record. */
    private static final int MAX_ITEMS = 20;

    private static final String ELLIPSIS = "…";

    private static final String CERTIFICATE_PAGE_PATH = "/cert-manager/manage/";

    private EmailText() {
    }

    /** A template field, trimmed and on one line, so it cannot add a header to a subject; "" when absent. */
    static String field(NotificationEvent event, String name) {
        Object value = event.getTemplateFields() == null ? null : event.getTemplateFields().get(name);
        return trimmed(value).replaceAll("[\\r\\n]+", " ");
    }

    static String trimmed(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    /** The value HTML-escaped, with '{' and '}' as character references; null is "". */
    static String escape(Object value) {
        if (value == null) {
            return "";
        }
        return HtmlUtils.htmlEscape(String.valueOf(value)).replace("{", "&#123;").replace("}", "&#125;");
    }

    /**
     * Escapes every template field the model holds, flattened and under "templateFields.", and drops
     * the raw {@code templateFields} map, which nothing escapes.
     */
    static void escapeTemplateFields(NotificationEvent event, Map<String, Object> model) {
        for (String field : flattenedKeys(event.getTemplateFields())) {
            model.computeIfPresent(field, (ignored, value) -> escape(value));
            model.computeIfPresent("templateFields." + field, (ignored, value) -> escape(value));
        }
        model.remove("templateFields");
    }

    /**
     * The certificate's page in the dashboard, or the dashboard without a reference. The reference is
     * path-encoded (braces included), then the whole address HTML-escaped.
     */
    static String certificatePage(Object frontendBaseUrl, Object certificateXref) {
        String base = trimmed(frontendBaseUrl);
        String xref = trimmed(certificateXref);
        if (xref.isEmpty()) {
            return HtmlUtils.htmlEscape(base);
        }
        return HtmlUtils.htmlEscape(base + CERTIFICATE_PAGE_PATH + UriUtils.encodePathSegment(xref, StandardCharsets.UTF_8));
    }

    /** A details row; the label is ours and the value already escaped. */
    static String detailRow(String label, String escapedValue) {
        return DETAIL_ROW_HTML.formatted(label, escapedValue);
    }

    /** The details panel around {@code rows}; empty when there is no row, so no empty panel remains. */
    static String detailsPanel(String rows) {
        return rows.isEmpty() ? "" : DETAILS_PANEL_START + rows + DETAILS_PANEL_END;
    }

    /** A body-copy row holding {@code text}, which must hold no publisher value. */
    static String copyRow(String text) {
        return COPY_ROW_HTML.formatted(text);
    }

    /**
     * One details row per {@code items} entry with a label (escaped), its count beside it; a count that is not a
     * whole number is left blank. "" when {@code items} is not a list or has no labelled entry.
     */
    static String itemRows(Object items) {
        if (!(items instanceof List<?> entries)) {
            return "";
        }
        StringBuilder rows = new StringBuilder();
        entries.stream()
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .filter(entry -> !trimmed(entry.get("label")).isEmpty())
                .limit(MAX_ITEMS)
                .forEach(entry -> rows.append(detailRow(escape(trimmed(entry.get("label"))),
                        wholeNumber(entry.get("count")))));
        return rows.toString();
    }

    /** Digits only, so nothing in it needs escaping. */
    private static String wholeNumber(Object count) {
        String number = trimmed(count);
        return number.matches("\\d{1,9}") ? number : "";
    }

    /** The subject cut to {@link #MAX_SUBJECT_LENGTH} with an ellipsis, never inside a surrogate pair. */
    static String subject(String subject) {
        if (subject.length() <= MAX_SUBJECT_LENGTH) {
            return subject;
        }
        return cut(subject, MAX_SUBJECT_LENGTH - ELLIPSIS.length()) + ELLIPSIS;
    }

    /**
     * {@code prefix + variable + suffix} within {@link #MAX_SUBJECT_LENGTH}: only the variable is cut,
     * with an ellipsis, so the fixed text around it always survives.
     */
    static String subject(String prefix, String variable, String suffix) {
        int room = MAX_SUBJECT_LENGTH - prefix.length() - suffix.length();
        if (variable.length() <= room) {
            return prefix + variable + suffix;
        }
        return prefix + cut(variable, Math.max(0, room - ELLIPSIS.length())) + ELLIPSIS + suffix;
    }

    private static String cut(String text, int length) {
        int end = length;
        if (end > 0 && Character.isHighSurrogate(text.charAt(end - 1))) {
            end--;
        }
        return text.substring(0, end);
    }

    /** Every template field key, nested maps flattened with dots ("domain.name"). */
    static List<String> flattenedKeys(Map<String, Object> templateFields) {
        List<String> keys = new ArrayList<>();
        if (templateFields != null) {
            collectKeys(templateFields, "", keys);
        }
        return keys;
    }

    private static void collectKeys(Map<?, ?> source, String prefix, List<String> keys) {
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            String key = prefix.isEmpty() ? String.valueOf(entry.getKey()) : prefix + "." + entry.getKey();
            if (entry.getValue() instanceof Map<?, ?> nested) {
                collectKeys(nested, key, keys);
            } else {
                keys.add(key);
            }
        }
    }
}
