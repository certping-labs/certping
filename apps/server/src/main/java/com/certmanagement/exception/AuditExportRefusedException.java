// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import org.springframework.http.HttpStatus;

/**
 * An audit trail export refused before any row was read: the HTTP status, a stable {@code code} the page can
 * branch on, a message it can show, and for {@code EXPORT_LIMIT} the seconds until a slot frees up
 * ({@code Retry-After}), as for {@code EXPORT_IN_PROGRESS} and {@code EXPORT_BUSY}.
 *
 * <ul>
 *   <li>400 {@link #TOO_LARGE}: more rows match than an export holds; narrow the range or the filters.</li>
 *   <li>429 {@link #LIMIT}: the organization made its exports for the hour.</li>
 *   <li>429 {@link #IN_PROGRESS}: another export of the organization holds its export lock; retry shortly.</li>
 *   <li>503 {@link #NOT_RECORDED}: the export's own audit row could not be written, so the export did not
 *       start (a read of the trail never happens unrecorded).</li>
 *   <li>503 {@link #BUSY}: this server is streaming as many exports as it allows at once; retry shortly.</li>
 *   <li>503 {@link #TIMEOUT}: the export did not start writing before the async request timed out.</li>
 * </ul>
 */
public class AuditExportRefusedException extends RuntimeException {

    public static final String TOO_LARGE = "EXPORT_TOO_LARGE";
    public static final String LIMIT = "EXPORT_LIMIT";
    public static final String NOT_RECORDED = "EXPORT_NOT_RECORDED";
    public static final String IN_PROGRESS = "EXPORT_IN_PROGRESS";
    public static final String BUSY = "EXPORT_BUSY";
    public static final String TIMEOUT = "EXPORT_TIMEOUT";

    private final HttpStatus status;
    private final String code;
    private final Long retryAfterSeconds;
    private final Integer maxRows;

    private AuditExportRefusedException(HttpStatus status, String code, String message, Long retryAfterSeconds,
                                        Integer maxRows) {
        super(message);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
        this.maxRows = maxRows;
    }

    public static AuditExportRefusedException tooLarge(int maxRows) {
        return new AuditExportRefusedException(HttpStatus.BAD_REQUEST, TOO_LARGE,
                "The export has more than " + String.format("%,d", maxRows) + " entries. Narrow the date range or "
                        + "the filters, and export the rest separately.", null, maxRows);
    }

    public static AuditExportRefusedException limit(int perHour, long retryAfterSeconds) {
        return new AuditExportRefusedException(HttpStatus.TOO_MANY_REQUESTS, LIMIT,
                "Your organization has made " + perHour + " audit log exports in the last hour. Try again later.",
                Math.max(1, retryAfterSeconds), null);
    }

    public static AuditExportRefusedException notRecorded() {
        return new AuditExportRefusedException(HttpStatus.SERVICE_UNAVAILABLE, NOT_RECORDED,
                "The export could not be recorded in the audit log, so it was not started. Try again in a few "
                        + "minutes.", null, null);
    }

    public static AuditExportRefusedException inProgress(long retryAfterSeconds) {
        return new AuditExportRefusedException(HttpStatus.TOO_MANY_REQUESTS, IN_PROGRESS,
                "Another audit log export of your organization is starting. Try again in a few seconds.",
                retryAfterSeconds, null);
    }

    public static AuditExportRefusedException busy(long retryAfterSeconds) {
        return new AuditExportRefusedException(HttpStatus.SERVICE_UNAVAILABLE, BUSY,
                "Too many audit log exports are running right now. Try again in a few seconds.", retryAfterSeconds,
                null);
    }

    public static AuditExportRefusedException timedOut() {
        return new AuditExportRefusedException(HttpStatus.SERVICE_UNAVAILABLE, TIMEOUT,
                "The export took too long to start. Narrow the date range or the filters, and try again.", null, null);
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    /** Seconds until the next export is allowed; {@code null} unless the limit was reached. */
    public Long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }

    /** The most rows an export holds; {@code null} unless the export was too large. */
    public Integer getMaxRows() {
        return maxRows;
    }
}
