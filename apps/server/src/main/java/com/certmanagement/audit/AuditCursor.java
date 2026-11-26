// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.exception.BadRequestException;
import com.fasterxml.jackson.annotation.JsonProperty;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.core.JacksonException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;

/**
 * The keyset cursor of the audit list:
 * base64url JSON of the last row's time and id, the number of the page it leads to, and the total
 * counted on the first page, so later pages need no count. It is opaque to the caller but not secret:
 * it only positions a page, and the scope, window and filters are enforced on every request whatever
 * it says. {@code a} records the direction it was made for, so a cursor never pages the other way.
 *
 * @param occurredAt the last row's time, to the microsecond
 * @param id         the last row's id; ties on time are broken by it
 * @param number     the page the cursor leads to (0-based)
 * @param total      the total counted on the first page (capped)
 * @param capped     whether that total is a lower bound
 * @param ascending  whether the pages run oldest first
 */
public record AuditCursor(
        @JsonProperty("t") String occurredAt,
        @JsonProperty("i") long id,
        @JsonProperty("n") int number,
        @JsonProperty("c") long total,
        @JsonProperty("x") boolean capped,
        @JsonProperty("a") boolean ascending) {

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();
    private static final String NOT_OURS = "cursor is not one this endpoint returned";

    public static AuditCursor after(AuditEventRecord last, int number, long total, boolean capped, boolean ascending) {
        return new AuditCursor(last.occurredAt().toString(), last.id(), number, total, capped, ascending);
    }

    public Instant at() {
        return Instant.parse(occurredAt);
    }

    public String encode() {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.writeValueAsBytes(this));
        } catch (JacksonException e) {
            throw new IllegalStateException("audit cursor could not be encoded", e);
        }
    }

    /** The cursor {@code encoded} stands for; a 400 for anything this endpoint did not return. */
    public static AuditCursor decode(String encoded) {
        AuditCursor cursor;
        try {
            byte[] json = Base64.getUrlDecoder().decode(encoded.trim());
            cursor = JSON.readValue(new String(json, StandardCharsets.UTF_8), AuditCursor.class);
            if (cursor.occurredAt() == null) {
                throw new BadRequestException(NOT_OURS);
            }
            cursor.at();
        } catch (IllegalArgumentException | JacksonException | DateTimeParseException e) {
            throw new BadRequestException(NOT_OURS);
        }
        if (cursor.id() <= 0 || cursor.number() < 0 || cursor.total() < 0) {
            throw new BadRequestException(NOT_OURS);
        }
        return cursor;
    }
}
