// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditAccessEntryDto;
import com.certmanagement.dto.audit.AuditEventEntryDto;
import com.certmanagement.dto.audit.AuditPlatformEntryDto;

import java.io.IOException;
import java.io.Writer;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * The CSV layouts of the exports: a stable header per view, and RFC 4180 rows. The activity header ends
 * with {@code category}, {@code reason} and {@code requestedByName}; the Access view has a header of its own; the
 * platform header is the activity one followed by the staff fields. Columns are only ever appended, so a
 * spreadsheet built on an older export keeps working.
 *
 * <p>Every text cell goes through {@link #cell}, the formula-injection guard: a summary, a name or an email can
 * start with {@code =}, {@code +}, {@code -} or {@code @} when a customer chose it, and a spreadsheet would run it.
 */
final class AuditCsv {

    static final List<String> ACTIVITY_HEADER = List.of(
            "timestamp", "action", "event", "summary", "status", "errorCode", "resource", "resourceId", "resourceName",
            "actorType", "actorName", "userId", "userEmail", "ipAddress", "requestId",
            "category", "reason", "requestedByName");

    static final List<String> ACCESS_HEADER = List.of(
            "timestamp", "activity", "target", "resourceId", "status", "errorCode", "actor", "userId", "userEmail",
            "ipAddress", "requestId", "correlationId");

    static final List<String> PLATFORM_HEADER = Stream.concat(ACTIVITY_HEADER.stream(), Stream.of(
            "organizationId", "organizationName", "visibility", "actor", "staff", "authMethod", "userAgent",
            "correlationId", "traceId")).toList();

    private AuditCsv() {
    }

    static List<String> activityRow(AuditEventEntryDto e) {
        return List.of(time(e.timestamp()), cell(e.action()), cell(e.event()), cell(e.summary()), cell(e.status()),
                cell(e.errorCode()), cell(e.resource()), number(e.resourceId()), cell(e.resourceName()),
                cell(e.actorType()), cell(e.actorName()), number(e.userId()), cell(e.userEmail()), cell(e.ipAddress()),
                cell(e.requestId()), cell(e.category()), cell(e.reason()), cell(e.requestedByName()));
    }

    static List<String> accessRow(AuditAccessEntryDto e) {
        return List.of(time(e.timestamp()), cell(e.activity()), cell(e.target()), number(e.resourceId()),
                cell(e.status()), cell(e.errorCode()), cell(e.actor()), number(e.userId()), cell(e.userEmail()),
                cell(e.ipAddress()), cell(e.requestId()), cell(e.correlationId()));
    }

    static List<String> platformRow(AuditPlatformEntryDto p) {
        AuditEventEntryDto e = p.entry();
        List<String> row = new ArrayList<>(activityRow(e));
        row.addAll(List.of(number(e.organizationId()), cell(e.organizationName()), cell(p.visibility()),
                cell(p.actor()), String.valueOf(p.staff()), cell(p.authMethod()), cell(e.userAgent()),
                cell(e.correlationId()), cell(p.traceId())));
        return row;
    }

    /**
     * A text value a spreadsheet cannot read as a formula: one starting with {@code = + - @}, a tab or a carriage
     * return is prefixed with an apostrophe. {@code null} is an empty cell.
     */
    static String cell(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return "=+-@\t\r".indexOf(value.charAt(0)) >= 0 ? "'" + value : value;
    }

    /** One CSV line: a field with a comma, a quote or a line break is quoted, its quotes doubled. */
    static void write(Writer out, List<String> fields) throws IOException {
        for (int i = 0; i < fields.size(); i++) {
            if (i > 0) {
                out.write(',');
            }
            String field = fields.get(i);
            if (field.indexOf(',') >= 0 || field.indexOf('"') >= 0 || field.indexOf('\n') >= 0
                    || field.indexOf('\r') >= 0) {
                out.write('"');
                out.write(field.replace("\"", "\"\""));
                out.write('"');
            } else {
                out.write(field);
            }
        }
        out.write("\r\n");
    }

    private static String number(Number value) {
        return value == null ? "" : value.toString();
    }

    private static String time(OffsetDateTime value) {
        return value == null ? "" : DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(value);
    }
}
