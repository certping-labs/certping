// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.constants;

/**
 * Error code strings stored in {@code certificates.last_error_code} and in the
 * {@code details} JSON of {@code certificate_events}.
 *
 * <p>These cannot be an enum because the field also receives free-form codes from
 * {@code certping-agent} via the message queue — the full value set is open.
 */
public final class ErrorCodes {

    public static final String QUEUE_PUBLISH_FAILED        = "QUEUE_PUBLISH_FAILED";
    public static final String DEPLOYMENT_CONFIG_MISSING = "DEPLOYMENT_CONFIG_MISSING";
    public static final String REVOCATION_PUBLISH_FAILED = "REVOCATION_PUBLISH_FAILED";

    /** Default reason written to {@code certificate_events.reason} when no reason is supplied. */
    public static final String DEFAULT_REVOCATION_REASON = "UNSPECIFIED";

    private ErrorCodes() {}
}
