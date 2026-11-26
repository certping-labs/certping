// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.exception;

import java.time.Duration;

/**
 * Thrown when a downstream provider (ACS or SMTP) responds
 * with a signal that the failure is transient — the same request should succeed
 * later, given time. Rate-limit responses (HTTP 429, "Retry-After") are the
 * canonical case.
 *
 * <p>The notifier's message handler catches this and hands off to
 * {@code ScheduledRetryService}, which clones the message body, stamps
 * {@code RetryCount + LastRetryReason + LastRetryAfterSec} application
 * properties, sets {@code ScheduledEnqueueTime = now + retryAfter}, sends the
 * future-dated copy back to the notifications channel, and completes the
 * original — matching the agent's {@code RetryableAgentException} pattern.
 */
public class RetryableNotificationException extends RuntimeException {

    private final String reasonCode;
    private final Duration retryAfter;

    public RetryableNotificationException(String reasonCode, String message, Duration retryAfter) {
        super(message);
        this.reasonCode = reasonCode;
        this.retryAfter = retryAfter;
    }

    public RetryableNotificationException(String reasonCode, String message, Duration retryAfter, Throwable cause) {
        super(message, cause);
        this.reasonCode = reasonCode;
        this.retryAfter = retryAfter;
    }

    public String getReasonCode() {
        return reasonCode;
    }

    public Duration getRetryAfter() {
        return retryAfter;
    }
}
