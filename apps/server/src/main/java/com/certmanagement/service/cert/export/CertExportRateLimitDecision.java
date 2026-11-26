// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

/** What {@link CertExportRateLimiter#tryAcquire} decided for one export attempt. */
public sealed interface CertExportRateLimitDecision {

    CertExportRateLimitDecision ALLOWED = new Allowed();

    /** Under the limit, or Redis was unreachable and the format carries no private key (fail open). */
    record Allowed() implements CertExportRateLimitDecision {
    }

    /**
     * Over the limit.
     *
     * @param retryAfterSeconds     seconds until the user's window resets
     * @param firstRefusalInWindow  true only for the attempt that first went over the limit in this
     *                              window, so callers can record one refusal per user per window
     */
    record Limited(long retryAfterSeconds, boolean firstRefusalInWindow) implements CertExportRateLimitDecision {
    }

    /** Redis was unreachable and the format carries a private key, so the attempt is refused (fail closed). */
    record LimiterUnavailable() implements CertExportRateLimitDecision {
    }
}
