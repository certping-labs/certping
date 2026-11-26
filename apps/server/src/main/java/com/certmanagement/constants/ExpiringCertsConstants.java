// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.constants;

/**
 * Bounds and defaults for the assistant expiring-certs window
 * ({@code GET /api/v1/certs/expiring}).
 */
public final class ExpiringCertsConstants {

    private ExpiringCertsConstants() {}

    /** Default look-ahead when {@code withinDays} is omitted. */
    public static final int DEFAULT_WITHIN_DAYS = 7;

    /** String form of {@link #DEFAULT_WITHIN_DAYS} for {@code @RequestParam} defaultValue. */
    public static final String DEFAULT_WITHIN_DAYS_PARAM = "7";

    public static final int MIN_WITHIN_DAYS = 1;

    public static final int MAX_WITHIN_DAYS = 90;

    /** Used when the service receives a null {@link org.springframework.data.domain.Pageable}. */
    public static final int DEFAULT_PAGE = 0;

    public static final int DEFAULT_PAGE_SIZE = 20;

    /** Ceiling for {@code size} on the assistant expiring-certs path (Spring default max is 2000). */
    public static final int MAX_PAGE_SIZE = 100;
}
