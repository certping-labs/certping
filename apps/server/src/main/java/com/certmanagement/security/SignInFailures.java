// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.exception.SsoMemberNotProvisionedException;
import com.certmanagement.exception.UnauthorizedException;
import org.springframework.security.core.AuthenticationException;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Turns a failed sign-in into what may be written about it: a reason code for the audit trail and the
 * {@code AUTH_EVENT} log line, and a message for the browser. Classified by the exception's type only,
 * never its message, so a hostname, a token endpoint URL, SQL or a vault name in an exception's text
 * cannot reach a log field, an audit row or a redirect.
 */
public final class SignInFailures {

    /** What the browser is told when the failure is not one of the platform's own refusals. */
    public static final String GENERIC_MESSAGE = "Sign-in failed. Please try again.";

    private static final Pattern PROVIDER_ERROR = Pattern.compile("^[a-z0-9_.-]{1,64}$");
    // Every reason a sign-in, sign-out or password flow can record. Each has a customer-safe sentence of
    // its own in AuditReason (AuditCatalogTest checks it); call sites take them from here.
    public static final AuditReason INVALID_CREDENTIALS = AuditReason.of("INVALID_CREDENTIALS");
    public static final AuditReason ACCOUNT_DISABLED = AuditReason.of("ACCOUNT_DISABLED");
    public static final AuditReason ACCOUNT_LOCKED = AuditReason.of("ACCOUNT_LOCKED");
    public static final AuditReason ORGANIZATION_SUSPENDED = AuditReason.of("ORGANIZATION_SUSPENDED");
    public static final AuditReason SIGN_IN_METHOD_NOT_ALLOWED = AuditReason.of("SIGN_IN_METHOD_NOT_ALLOWED");
    public static final AuditReason SSO_REJECTED = AuditReason.of("SSO_REJECTED");
    public static final AuditReason SSO_MISCONFIGURED = AuditReason.of("SSO_MISCONFIGURED");
    public static final AuditReason SSO_MEMBER_NOT_PROVISIONED = AuditReason.of("SSO_MEMBER_NOT_PROVISIONED");
    public static final AuditReason FEATURE_DISABLED = AuditReason.of("FEATURE_DISABLED");
    /** The person cancelled at the identity provider (closed or declined its consent screen). */
    public static final AuditReason SIGN_IN_CANCELLED = AuditReason.of("SIGN_IN_CANCELLED");
    /** The password was right but the one-time code (or recovery code) was not, or the challenge had expired. */
    public static final AuditReason MFA_CODE_INVALID = AuditReason.of("MFA_CODE_INVALID");

    /**
     * The reasons the auth flows record, besides {@link AuditReason#INTERNAL_ERROR} (anything unexpected,
     * which names the request id to quote to support).
     */
    public static final Set<AuditReason> REASONS = Set.of(INVALID_CREDENTIALS, ACCOUNT_DISABLED, ACCOUNT_LOCKED,
            ORGANIZATION_SUSPENDED, SIGN_IN_METHOD_NOT_ALLOWED, SSO_REJECTED, SSO_MISCONFIGURED,
            SSO_MEMBER_NOT_PROVISIONED, FEATURE_DISABLED, SIGN_IN_CANCELLED, MFA_CODE_INVALID);

    /** Provider error codes that mean the person cancelled, for every identity provider. */
    private static final Set<String> CANCELLED = Set.of("access_denied");
    /** Microsoft's own codes for a person declining or closing its consent screen. */
    private static final Set<String> MICROSOFT_CANCELLED = Set.of("consent_required", "user_cancelled");

    private SignInFailures() {
    }

    /**
     * The reason a federated (single sign-on) sign-in failed: the platform's own refusal keeps its
     * code; the provider or the flow refusing it ({@code 400/401/403}-class exceptions, a framework
     * authentication failure) is {@code SSO_REJECTED}; anything else is {@code INTERNAL_ERROR}.
     */
    public static AuditReason reasonOf(Throwable failure) {
        if (failure instanceof SignInRefusedException refused) {
            return refused.reason();
        }
        if (failure instanceof FeatureDisabledException) {
            return FEATURE_DISABLED;
        }
        if (failure instanceof SsoMemberNotProvisionedException) {
            return SSO_MEMBER_NOT_PROVISIONED;
        }
        if (failure instanceof UnauthorizedException || failure instanceof ForbiddenException
                || failure instanceof BadRequestException || failure instanceof AuthenticationException) {
            return SSO_REJECTED;
        }
        return AuditReason.INTERNAL_ERROR;
    }

    /**
     * The reason an identity provider sent the person back with {@code ?error=}: {@link #SIGN_IN_CANCELLED} when
     * its code means they cancelled, else {@link #SSO_REJECTED}. Only a clean short code counts, as for
     * {@link #providerErrorCode}; free text never matches.
     */
    public static AuditReason providerRefusalReason(String provider, String error) {
        String code = providerErrorCode(error);
        if (CANCELLED.contains(code) || ("microsoft".equals(provider) && MICROSOFT_CANCELLED.contains(code))) {
            return SIGN_IN_CANCELLED;
        }
        return SSO_REJECTED;
    }

    /** The account a refused sign-in resolved to, or null. */
    public static SignInAccount accountOf(Throwable failure) {
        return failure instanceof SignInRefusedException refused ? refused.account() : null;
    }

    /** The exception's class for a log line's {@code cause} field: a type, never its text. */
    public static String causeOf(Throwable failure) {
        return failure == null ? "none" : failure.getClass().getSimpleName();
    }

    /**
     * What the browser is told: the platform's own refusals were written for the person signing in and keep
     * their message; anything else (a provider's token endpoint failing, a database error) gets
     * {@link #GENERIC_MESSAGE}, so its text never reaches a redirect URL.
     */
    public static String clientMessage(Throwable failure) {
        if (failure instanceof UnauthorizedException || failure instanceof ForbiddenException
                || failure instanceof BadRequestException || failure instanceof FeatureDisabledException) {
            String message = failure.getMessage();
            return message == null || message.isBlank() ? GENERIC_MESSAGE : message;
        }
        return GENERIC_MESSAGE;
    }

    /**
     * An identity provider's error code ({@code access_denied}, {@code invalid_signature}) fit for a log
     * field: lower-cased and kept only when it is a short code; anything else (free text, an injected line
     * break) reads {@code other}.
     */
    public static String providerErrorCode(String error) {
        if (error == null || error.isBlank()) {
            return "none";
        }
        String code = error.trim().toLowerCase(Locale.ROOT);
        return PROVIDER_ERROR.matcher(code).matches() ? code : "other";
    }
}
