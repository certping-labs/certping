// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.scheduler;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Unified response body for all internal scheduler endpoints.
 *
 * <p>Fields that are not applicable to a given job are omitted from the JSON
 * response via {@code @JsonInclude(NON_NULL)}.</p>
 *
 * <p>Callers should always check {@code errors} even
 * when the HTTP status is 200 — jobs apply best-effort semantics per cert/organization
 * and a partial failure does not fail the whole HTTP request.</p>
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SchedulerJobResult {

    /** Job name, e.g. "trigger-renewals" */
    private String job;

    /** ISO-8601 timestamp when the server began processing */
    @Builder.Default
    private String triggeredAt = Instant.now().toString();

    /** true when the caller sent dryRun=true */
    private Boolean dryRun;

    // ---- trigger-renewals counters ----
    private Integer triggered;
    private Integer skipped;
    /** Generic count of records/subscriptions inspected by jobs that do not use trigger semantics. */
    private Integer scanned;
    /** Generic count of external reports/messages emitted by jobs that do not use trigger semantics. */
    private Integer reported;
    /** Populated only in dry-run mode */
    private Integer wouldTrigger;
    /** Populated only in dry-run mode */
    private Integer wouldSkip;

    // ---- mark-expired-certs counter ----
    private Integer marked;

    // ---- trigger-expiry-alerts counters ----
    private Integer alerted;
    private Integer daysBeforeExpiry;

    /** Per-cert / per-organization detail entries */
    @Builder.Default
    private List<Map<String, Object>> details = new ArrayList<>();

    /** Per-cert / per-organization error entries — non-empty means partial failure */
    @Builder.Default
    private List<Map<String, Object>> errors = new ArrayList<>();

    /** Human-readable note set when the job was skipped (e.g. due to a disabled feature flag). */
    private String note;

    /**
     * Factory for a no-op result returned when a feature flag gate prevented the job from running.
     */
    public static SchedulerJobResult skipped(String reason) {
        return SchedulerJobResult.builder()
                .triggered(0)
                .skipped(0)
                .note(reason)
                .build();
    }
}
