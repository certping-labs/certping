// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Owns the canonical, non-user-spoofable marker embedded in Intune profile descriptions. */
final class IntuneProfileMarker {
    private static final Pattern VALID_MARKER = Pattern.compile(
            "certping:[A-Za-z0-9:_-]{1,190}");
    private static final Pattern MARKER_LIKE_TEXT = Pattern.compile(
            "(?i)\\[\\s*certping:");
    private static final Pattern CANONICAL_SUFFIX = Pattern.compile(
            "(?:^|\\R)Managed by CertPing \\[(certping:[A-Za-z0-9:_-]{1,190})]\\s*$");

    private IntuneProfileMarker() {
    }

    static String appendTo(String userDescription, String marker) {
        String validatedMarker = requireValid(marker);
        String description = trimToNull(userDescription);
        if (description != null && MARKER_LIKE_TEXT.matcher(description).find()) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    "description must not contain a CertPing ownership marker");
        }
        String suffix = "Managed by CertPing [" + validatedMarker + "]";
        return description == null ? suffix : description + "\n" + suffix;
    }

    static String extract(String description) {
        if (description == null) {
            return null;
        }
        Matcher matcher = CANONICAL_SUFFIX.matcher(description);
        return matcher.find() ? matcher.group(1) : null;
    }

    static String requireValid(String marker) {
        String value = trimToNull(marker);
        if (value == null || !VALID_MARKER.matcher(value).matches()) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    "providerCorrelationMarker is invalid");
        }
        return value;
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
