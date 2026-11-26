// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.validation;

import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Set;

/**
 * Collapses the several ways Microsoft Graph expresses "no value" into a plain null.
 *
 * <p>Verified against a live Intune tenant. Graph does not return nulls consistently:
 * <ul>
 *   <li>empty strings rather than null ({@code serialNumber: ""} on a stale enrollment)</li>
 *   <li>the literal {@code "Unknown"} for device category and owner type</li>
 *   <li>{@code "0.0.0.0"} for an OS version that was never reported</li>
 *   <li>sentinel dates {@code 0001-01-01} and {@code 9999-12-31}</li>
 *   <li>an all-zero GUID for a device that is not Entra-registered</li>
 * </ul>
 *
 * <p>Worse, the <em>same field</em> differs between the collection and single-device
 * endpoints — {@code udid} is null from the list call and {@code ""} from the single GET.
 * Without normalisation the same unchanged device diffs as changed depending on which
 * call fetched it, so the "no change, no event" rule never fires and the audit table
 * grows by fleet-size on every sync.
 *
 * <p>Applied defensively on ingest even though the agent normalises first: the REST door
 * is open to scripts and imports that may not have.
 */
@Component
public class DeviceFieldNormalizer {

    private static final String ZERO_GUID = "00000000-0000-0000-0000-000000000000";

    /** Values that mean "absent" rather than a real reading. */
    private static final Set<String> SENTINEL_VALUES = Set.of("unknown", "0.0.0.0", "none");

    private static final int SENTINEL_MIN_YEAR = 2;
    private static final int SENTINEL_MAX_YEAR = 9998;

    /** Blank and whitespace-only strings become null. */
    public String text(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * As {@link #text} but also rejects Graph's placeholder values. Use for fields where
     * {@code "Unknown"} is a stand-in for null — device category, owner type, OS version.
     * Do <em>not</em> use for {@code jailBroken}, where {@code "Unknown"} is a genuine
     * tri-state reading on a healthy device.
     */
    public String textOrSentinel(String value) {
        String normalized = text(value);
        if (normalized == null) {
            return null;
        }
        return SENTINEL_VALUES.contains(normalized.toLowerCase()) ? null : normalized;
    }

    /** An all-zero GUID means the device is not Entra-registered, not that it has that id. */
    public String guid(String value) {
        String normalized = text(value);
        if (normalized == null) {
            return null;
        }
        return ZERO_GUID.equalsIgnoreCase(normalized) ? null : normalized;
    }

    /**
     * Drops Graph's sentinel dates and truncates to seconds.
     *
     * <p>Truncation is not cosmetic: the collection endpoint returns second precision
     * ({@code 2026-08-12T06:16:04Z}) while the single-device endpoint returns sub-second
     * ({@code ...04.0600932Z}). Comparing them raw makes every device look changed.
     */
    public OffsetDateTime timestamp(OffsetDateTime value) {
        if (value == null) {
            return null;
        }
        int year = value.getYear();
        if (year <= SENTINEL_MIN_YEAR || year >= SENTINEL_MAX_YEAR) {
            return null;
        }
        return value.truncatedTo(ChronoUnit.SECONDS);
    }

    /** Graph returns {@code company} / {@code personal} / {@code unknown} in lower case. */
    public String ownerType(String value) {
        String normalized = text(value);
        return normalized == null ? null : normalized.toUpperCase();
    }

    /** True when two normalised values differ, treating null and blank as equal. */
    public boolean changed(Object before, Object after) {
        if (before == null && after == null) {
            return false;
        }
        if (before == null || after == null) {
            return true;
        }
        return !before.equals(after);
    }
}
