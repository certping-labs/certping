// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The customer partial indexes are on {@code visibility = 'CUSTOMER'}, and Postgres can
 * use them under a generic plan only when the query spells that literal. A bound parameter
 * ({@code visibility = :visibility}, {@code visibility IN (:v)}, {@code visibility = ?}) silently loses them, so no SQL string in
 * the audit package may compare visibility with one.
 */
class AuditSqlGuardTest {

    static final Pattern BOUND_VISIBILITY =
            Pattern.compile("visibility\\s*(=|<>|!=|IN)\\s*\\(?\\s*[:?]", Pattern.CASE_INSENSITIVE);
    private static final Pattern TEXT_BLOCK = Pattern.compile("\"\"\"(.*?)\"\"\"", Pattern.DOTALL);
    private static final Pattern LITERAL = Pattern.compile("\"((?:\\\\.|[^\"\\\\\\n])*)\"");
    private static final Path SOURCES = Path.of("src/main/java/com/certmanagement/audit");

    @Test
    void noAuditSqlBindsVisibility() throws IOException {
        List<String> offenders = new ArrayList<>();
        try (Stream<Path> files = Files.list(SOURCES)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                if (BOUND_VISIBILITY.matcher(stringConstants(Files.readString(file))).find()) {
                    offenders.add(file.getFileName().toString());
                }
            }
        }
        assertThat(offenders).as("SQL comparing visibility with a bound parameter").isEmpty();
    }

    @Test
    void theGuardCatchesTheShapesItIsFor() {
        assertThat(List.of("WHERE visibility = :visibility", "where VISIBILITY<>:v", "visibility != :v",
                "visibility IN (:visibilities)", "visibility in(:v)", "WHERE visibility = ?",
                "visibility IN (?, ?)", "visibility<>?"))
                .allSatisfy(sql -> assertThat(BOUND_VISIBILITY.matcher(sql).find()).as(sql).isTrue());
        assertThat(List.of("WHERE visibility = 'CUSTOMER'", "visibility IN ('CUSTOMER', 'INTERNAL')",
                "organization_id = :organizationId"))
                .allSatisfy(sql -> assertThat(BOUND_VISIBILITY.matcher(sql).find()).as(sql).isFalse());
        assertThat(stringConstants("String sql = \"SELECT * FROM audit_events WHERE visibility = \" + \":v\";"))
                .as("concatenated literals are joined").matches(s -> BOUND_VISIBILITY.matcher(s).find());
    }

    /** Every string literal and text block in the source, joined with spaces. */
    static String stringConstants(String source) {
        StringBuilder constants = new StringBuilder();
        Matcher blocks = TEXT_BLOCK.matcher(source);
        while (blocks.find()) {
            constants.append(blocks.group(1)).append(' ');
        }
        Matcher literals = LITERAL.matcher(TEXT_BLOCK.matcher(source).replaceAll(" "));
        while (literals.find()) {
            constants.append(literals.group(1)).append(' ');
        }
        return constants.toString();
    }
}
