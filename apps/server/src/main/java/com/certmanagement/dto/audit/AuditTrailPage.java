// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * One page of the Access view or the platform view: the same page fields as {@link AuditEventPageResponse}
 * (Spring's page fields, the capped total, the keyset cursor and the start of the visible window), around
 * that view's entries.
 *
 * @param <T> the view's entry
 */
@Schema(description = "One page of audit entries")
public record AuditTrailPage<T>(

        @Schema(description = "Entries on this page, newest first")
        List<T> content,

        @Schema(description = "Page number (0-indexed)", example = "0")
        int number,

        @Schema(description = "Page size", example = "20")
        int size,

        @Schema(description = "Matching entries; when totalElementsCapped, a lower bound (the count cap)", example = "150")
        long totalElements,

        @Schema(description = "Pages of totalElements", example = "8")
        int totalPages,

        @Schema(description = "Whether this is the first page", example = "true")
        boolean first,

        @Schema(description = "Whether no page follows this one", example = "false")
        boolean last,

        @Schema(description = "Entries on this page", example = "20")
        int numberOfElements,

        @Schema(description = "Whether this page has no entries", example = "false")
        boolean empty,

        @Schema(description = "True when more entries match than were counted, so totalElements is a lower bound",
                example = "false")
        boolean totalElementsCapped,

        @Schema(description = "Pass as cursor to read the next page; null on the last page", nullable = true)
        String nextCursor,

        @Schema(description = "Earliest time this reader may see; null when the view is not clamped (platform)",
                example = "2026-07-09T09:30:00Z", nullable = true)
        OffsetDateTime visibleFrom) {
}
