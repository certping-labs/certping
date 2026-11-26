// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The row as the store writes it, within its limits:
 * every string cut to its byte limit on a code-point boundary, unpaired surrogates replaced (Postgres
 * refuses invalid UTF-8 and would lose the whole row), NUL and other control characters removed, and
 * the value of any change or attribute replaced by {@link #REDACTED} when its name marks it as a secret
 * or the value itself looks like one (a PEM block, a SAS token or connection string, a JWT).
 */
public final class AuditSanitizer {

    public static final String REDACTED = "[REDACTED]";

    static final int SHORT_MAX = 256;
    static final int TEXT_MAX = 1024;
    static final int VALUE_MAX = 2048;

    /**
     * Names are compared lower-cased without separators, so apiKey, api_key and API-KEY all match. These
     * are long enough to match anywhere in a name.
     */
    private static final List<String> SECRET_ANYWHERE = List.of("password", "passwd", "passphrase", "secret",
            "privatekey", "privkey", "connectionstring", "accountkey", "storagekey", "sasurl",
            "keystore", "pkcs12", "tsig", "hmac", "authorization", "bearer", "cookie");
    /**
     * A name ending in one of these is a secret; one that only starts with or contains it is not, so
     * tokenPrefix, sasEnabled, pemFormat, jwtIssuer, signatureAlgorithm, signedIn, design and assignee all
     * stay readable.
     * The short ones (sig, sas, otp, pem, pfx, jwt) are only ever matched here, never as a substring.
     */
    private static final List<String> SECRET_SUFFIX = List.of("token", "authcode", "apikey", "eppcode", "credjson",
            "signature", "sig", "sas", "otp", "pem", "pfx", "jwt");
    /** Values that are secrets whatever they are called. */
    private static final List<String> SECRET_VALUE_MARKERS =
            List.of("-----begin", "sharedaccesssignature", "sig=", "accountkey=");
    private static final Pattern JWT = Pattern.compile("eyJ[\\w-]+\\.[\\w-]+\\.[\\w-]+");

    private AuditSanitizer() {
    }

    public static AuditEventRow sanitize(AuditEventRow row) {
        return row.toBuilder()
                .event(text(row.event(), SHORT_MAX))
                .category(text(row.category(), SHORT_MAX))
                .featureKey(text(row.featureKey(), SHORT_MAX))
                .actorLabel(text(row.actorLabel(), SHORT_MAX))
                .actorJob(text(row.actorJob(), SHORT_MAX))
                .authMethod(text(row.authMethod(), SHORT_MAX))
                .action(text(row.action(), SHORT_MAX))
                .resourceType(text(row.resourceType(), SHORT_MAX))
                .resourceRef(text(row.resourceRef(), SHORT_MAX))
                .resourceName(text(row.resourceName(), SHORT_MAX))
                .errorCode(text(row.errorCode(), SHORT_MAX))
                .summary(text(row.summary(), TEXT_MAX))
                .details(details(row.details()))
                .ipAddress(text(row.ipAddress(), SHORT_MAX))
                .userAgent(text(row.userAgent(), SHORT_MAX))
                .requestId(text(row.requestId(), SHORT_MAX))
                .correlationId(text(row.correlationId(), SHORT_MAX))
                .traceId(text(row.traceId(), SHORT_MAX))
                .build();
    }

    /** Whether a field of this name must never be stored in the clear. */
    public static boolean isSecretName(String name) {
        if (name == null) {
            return false;
        }
        StringBuilder normalised = new StringBuilder(name.length());
        for (char c : name.toLowerCase(Locale.ROOT).toCharArray()) {
            if (c != '_' && c != '-' && c != '.' && c != ' ') {
                normalised.append(c);
            }
        }
        String n = normalised.toString();
        return SECRET_ANYWHERE.stream().anyMatch(n::contains) || SECRET_SUFFIX.stream().anyMatch(n::endsWith);
    }

    private static AuditDetails details(AuditDetails details) {
        if (details.isEmpty()) {
            return details;
        }
        List<AuditChange> changes = new ArrayList<>(details.changes().size());
        for (AuditChange change : details.changes()) {
            changes.add(new AuditChange(text(change.field(), SHORT_MAX),
                    secret(change.field(), change.before()), secret(change.field(), change.after())));
        }
        Map<String, String> attributes = new LinkedHashMap<>();
        details.attributes().forEach((name, value) -> attributes.put(text(name, SHORT_MAX), secret(name, value)));
        return new AuditDetails(changes, attributes);
    }

    private static String secret(String name, String value) {
        if (value != null && !value.isEmpty() && (isSecretName(name) || isSecretValue(value))) {
            return REDACTED;
        }
        return text(value, VALUE_MAX);
    }

    /** Whether a value has the shape of a secret: a PEM block, a SAS token, a storage key, a JWT. */
    static boolean isSecretValue(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        return SECRET_VALUE_MARKERS.stream().anyMatch(lower::contains) || JWT.matcher(value).find();
    }

    /**
     * {@code value} without control characters (tab and newline kept) or unpaired surrogates, cut to at
     * most {@code maxBytes} of UTF-8 without splitting a character.
     */
    static String text(String value, int maxBytes) {
        if (value == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(Math.min(value.length(), maxBytes));
        int bytes = 0;
        int i = 0;
        while (i < value.length()) {
            char c = value.charAt(i);
            int codePoint;
            int width;
            if (Character.isHighSurrogate(c) && i + 1 < value.length() && Character.isLowSurrogate(value.charAt(i + 1))) {
                codePoint = Character.toCodePoint(c, value.charAt(i + 1));
                width = 2;
            } else if (Character.isSurrogate(c)) {
                codePoint = 0xFFFD;
                width = 1;
            } else {
                codePoint = c;
                width = 1;
            }
            i += width;
            if (Character.isISOControl(codePoint) && codePoint != '\t' && codePoint != '\n') {
                continue;
            }
            int size = utf8Length(codePoint);
            if (bytes + size > maxBytes) {
                break;
            }
            bytes += size;
            out.appendCodePoint(codePoint);
        }
        return out.toString();
    }

    private static int utf8Length(int codePoint) {
        if (codePoint < 0x80) {
            return 1;
        }
        if (codePoint < 0x800) {
            return 2;
        }
        return codePoint < 0x10000 ? 3 : 4;
    }
}
