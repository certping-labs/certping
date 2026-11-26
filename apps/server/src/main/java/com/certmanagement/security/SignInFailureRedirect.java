// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.audit.AuditReason;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * The frontend URL a failed single sign-on is sent back to. Besides the
 * {@code error}/{@code message} pair every client already reads, it carries:
 * <ul>
 *   <li>{@code reason}: the stable reason code, only when it is one of {@link SignInFailures#REASONS};
 *       anything else ({@code INTERNAL_ERROR}) is left out, and the page shows its generic message.</li>
 *   <li>{@code ref}: the request id the audit row and the {@code AUTH_EVENT} line carry, for the person to
 *       quote to their administrator or to support. It is left out unless it is a short, plain token.</li>
 * </ul>
 * Every value is percent-encoded, so a provider's free text in {@code message} cannot add or override a
 * parameter. Nothing here reads an exception.
 */
public final class SignInFailureRedirect {

    /** Sign-in callbacks mint their request ids ({@code req-http-<uuid>}, see {@link SignInRequestIds}). */
    private static final Pattern REFERENCE = Pattern.compile("^[A-Za-z0-9._:-]{1,128}$");

    private SignInFailureRedirect() {
    }

    public static String url(String frontendRedirectUrl, String message, AuditReason reason, String requestId) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(frontendRedirectUrl)
                .queryParam("error", "authentication_failed")
                .queryParam("message", encode(message == null ? "" : message));
        String code = reasonCode(reason);
        if (code != null) {
            builder.queryParam("reason", code);
        }
        String reference = reference(requestId);
        if (reference != null) {
            builder.queryParam("ref", encode(reference));
        }
        return builder.build(true).toUriString();
    }

    /** The code to put on the redirect, or null when it is not one of the sign-in reasons. */
    static String reasonCode(AuditReason reason) {
        return reason != null && SignInFailures.REASONS.contains(reason) ? reason.code() : null;
    }

    /** The request id to quote, or null when there is none or it is not a plain token. */
    static String reference(String requestId) {
        if (requestId == null || "unknown".equals(requestId)) {
            return null;
        }
        return REFERENCE.matcher(requestId).matches() ? requestId : null;
    }

    private static String encode(String value) {
        return UriUtils.encode(value, StandardCharsets.UTF_8);
    }
}
