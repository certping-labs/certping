// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public final class GcpNameUtils {

    private static final DateTimeFormatter VERSION_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC);

    /** Reserve room for the {@code -yyyyMMddHHmmss} suffix added by {@link #versionedId(String)}. */
    private static final int BASE_NAME_MAX_LEN = 48;

    /** Trailing chars from the cert xref to mix into the base name for uniqueness. */
    private static final int XREF_SUFFIX_LEN = 10;

    private GcpNameUtils() {}

    public static String toResourceId(String raw, String fallback) {
        String base = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        if (base.isBlank()) {
            base = fallback == null ? "certping" : fallback;
        }
        base = base.replace('.', '-').replace('_', '-').replace(' ', '-');
        base = base.replaceAll("[^a-z0-9-]", "-");
        base = base.replaceAll("-+", "-");
        base = base.replaceAll("^-+", "").replaceAll("-+$", "");
        if (base.isBlank()) {
            base = "certping";
        }
        return trimToLength(base, 63);
    }

    public static String versionedId(String baseName) {
        String normalized = toResourceId(baseName, "certping");
        String suffix = VERSION_FORMAT.format(Instant.now());
        return trimToLength(normalized + "-" + suffix, 63);
    }

    /**
     * Derive a stable, collision-resistant GCP Certificate base name from the cert's primary domain
     * and xref. Output is normalized to GCP resource-name rules and capped so that
     * {@link #versionedId(String)} stays within GCP's 63-char limit.
     *
     * <p>Format: {@code {domain-normalized}-{xref-suffix}} where {@code xref-suffix} is the trailing
     * {@value #XREF_SUFFIX_LEN} alphanumeric chars of the cert xref. The xref guarantees uniqueness
     * even when two CertPing certs cover the same domain on the same project.
     */
    public static String deriveBaseName(String domain, String certXref) {
        String domainPart = toResourceId(domain, "cert");
        String xref = certXref == null ? "" : certXref.toLowerCase(Locale.ROOT);
        String xrefSuffix = xref.replaceAll("[^a-z0-9]", "");
        if (xrefSuffix.length() > XREF_SUFFIX_LEN) {
            xrefSuffix = xrefSuffix.substring(xrefSuffix.length() - XREF_SUFFIX_LEN);
        }
        String combined = xrefSuffix.isEmpty() ? domainPart : domainPart + "-" + xrefSuffix;
        return trimToLength(combined, BASE_NAME_MAX_LEN);
    }

    private static String trimToLength(String value, int maxLen) {
        if (value.length() <= maxLen) {
            return value;
        }
        return value.substring(0, maxLen).replaceAll("-+$", "");
    }
}
