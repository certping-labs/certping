// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.dto.audit.AuditEventEntryDto;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** The export's CSV: a stable header per view, the formula-injection guard, and RFC 4180 quoting. */
class AuditCsvTest {

    @Test
    void theActivityHeaderKeepsItsColumnsThenCategoryReasonAndRequester() {
        // The original export columns, unchanged, then category, reason and requester.
        assertThat(AuditCsv.ACTIVITY_HEADER).containsExactly(
                "timestamp", "action", "event", "summary", "status", "errorCode", "resource", "resourceId",
                "resourceName", "actorType", "actorName", "userId", "userEmail", "ipAddress", "requestId",
                "category", "reason", "requestedByName");
        assertThat(AuditCsv.ACCESS_HEADER).containsExactly(
                "timestamp", "activity", "target", "resourceId", "status", "errorCode", "actor", "userId", "userEmail",
                "ipAddress", "requestId", "correlationId");
        assertThat(AuditCsv.PLATFORM_HEADER.subList(0, AuditCsv.ACTIVITY_HEADER.size()))
                .as("the platform columns are appended").isEqualTo(AuditCsv.ACTIVITY_HEADER);
        assertThat(AuditCsv.PLATFORM_HEADER).endsWith("organizationId", "organizationName", "visibility", "actor",
                "staff", "authMethod", "userAgent", "correlationId", "traceId");
    }

    @Test
    void aCellASpreadsheetWouldRunAsAFormulaIsPrefixed() {
        assertThat(List.of("=HYPERLINK(\"http://x\")", "+1", "-2", "@SUM(A1)", "\tcmd", "\rcmd"))
                .allSatisfy(value -> assertThat(AuditCsv.cell(value)).isEqualTo("'" + value));
        assertThat(AuditCsv.cell("Deleted the credential 'a=b'")).isEqualTo("Deleted the credential 'a=b'");
        assertThat(AuditCsv.cell(null)).isEmpty();
        assertThat(AuditCsv.cell("")).isEmpty();
    }

    @Test
    void everyTextCellOfARowIsGuardedAndQuotedWhereNeeded() throws IOException {
        AuditEventEntryDto entry = AuditEventEntryDto.builder()
                .timestamp(OffsetDateTime.parse("2026-10-07T09:30:00.123456Z"))
                .action("DELETE").event("credential.deleted")
                .summary("=cmd|' /C calc'!A0, \"quoted\"")
                .status("SUCCESS").resource("CREDENTIAL").resourceId(12L).resourceName("@evil")
                .actorType("USER").actorName("-Mallory").userId(42).userEmail("+mallory@example.com")
                .ipAddress("203.0.113.7").requestId("req-1").category("CREDENTIALS")
                .reason(null).requestedByName("Alice\nAdmin")
                .build();
        StringWriter out = new StringWriter();

        AuditCsv.write(out, AuditCsv.activityRow(entry));

        assertThat(out.toString()).isEqualTo("2026-10-07T09:30:00.123456Z,DELETE,credential.deleted,"
                + "\"'=cmd|' /C calc'!A0, \"\"quoted\"\"\",SUCCESS,,CREDENTIAL,12,'@evil,USER,'-Mallory,42,"
                + "'+mallory@example.com,203.0.113.7,req-1,CREDENTIALS,,\"Alice\nAdmin\"\r\n");
        assertThat(AuditCsv.activityRow(entry)).hasSize(AuditCsv.ACTIVITY_HEADER.size());
    }
}
