// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditDisplayNames;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.constants.JwtClaims;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.SignInAccount;
import com.certmanagement.security.SignInFailures;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.Metrics;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Writes the sign-in events of the audit trail: signed in, a sign-in refused, signed out, a password
 * changed, a reset requested and completed.
 *
 * <p>The actor is the account the event is for, set with {@link AuditScope#user} while the row is built:
 * at sign-in the request carries no token yet, so the request's own actor would be anonymous. Rows are
 * built on the request thread, so they keep its client address, user agent and ids even when the async
 * writer stores them later. The single sign-on callbacks, which run outside the {@code /api} interceptor,
 * resolve the client address themselves ({@link com.certmanagement.security.SignInCallbackClient}).
 *
 * <p>Which trail a row lands in:
 * <ul>
 *   <li>a customer account's rows land in its organization's trail;</li>
 *   <li>a platform staff account's (a super admin, or no organization) are internal, marked as staff:
 *       staff have no customer trail ({@link AuditEvents#platformOnly}); a staff lockout, written by
 *       CertPing, is internal too;</li>
 *   <li>a sign-in refused for an identifier no account has is an internal anonymous row that names no
 *       one: the identifier someone typed is never stored, nor anything derived from it.</li>
 * </ul>
 *
 * <p>A single sign-on attempt that came through an organization's configuration but matched no member (the
 * IdP rejected it, its signature did not verify, the configuration is off or incomplete, the person has no
 * member account) is also written into that organization's trail, so its admins see their single
 * sign-on failing: an anonymous "Someone" with the reason, the method and the registration id only, never
 * a client address or user agent (who called is unknown until an assertion is validated). At most one such
 * row per organization and reason every five minutes; the internal row is kept for support as before.
 *
 * <p>Refused sign-ins and reset requests are throttled to one row per account (or, for unknown
 * identifiers, per client address; never under one shared key when the address is unknown) per event per
 * minute, as {@code CertExportAuditRecorder} throttles
 * repeatable refusals; the rows held back are counted ({@code certping_audit_throttled_total}).
 *
 * <p>Write paths:
 * <ul>
 *   <li>a sign-in is queued for the async writer once the sign-in's transaction commits (now, when there
 *       is none), so a rolled-back sign-in leaves no row and the audit write never fails or slows it;</li>
 *   <li>a refusal, a sign-out and a reset request are queued at once ({@link AuditRecorder#recordFailure},
 *       {@link AuditRecorder#recordAsync}): none is in a transaction that must commit, and a reset request
 *       must answer the same whether or not a row could be written, so it never reveals an account;</li>
 *   <li>a password change and a completed reset are written in the change's own transaction
 *       ({@link AuditRecorder#record}, which requires one): they commit together.</li>
 * </ul>
 */
@Slf4j
@Component
public class AuthAuditRecorder {

    static final String THROTTLED_METRIC = "certping.audit.throttled";
    /** Exported as {@code certping_auth_lockouts_total{staff="true|false"}}. */
    static final String LOCKOUTS_METRIC = "certping.auth.lockouts";
    private static final String LOCKOUT_JOB = "account-lockout";
    private static final Duration THROTTLE_EVERY = Duration.ofMinutes(1);
    /** How often an organization's trail gets a row for the same single sign-on failure at most. */
    static final Duration ORGANIZATION_THROTTLE_EVERY = Duration.ofMinutes(5);
    /** Bounds the throttle's memory whatever the number of accounts and addresses being refused. */
    private static final int THROTTLE_MAX_KEYS = 10_000;
    private static final AuditReason INVALID_CREDENTIALS = SignInFailures.INVALID_CREDENTIALS;

    /** How someone signs in: the {@code method} attribute the sentence reads, and the session's auth method. */
    public enum Method {
        PASSWORD(JwtClaims.AUTH_METHOD_LOCAL),
        OIDC(JwtClaims.AUTH_METHOD_SSO),
        GOOGLE(JwtClaims.AUTH_METHOD_SOCIAL),
        MICROSOFT(JwtClaims.AUTH_METHOD_SOCIAL),
        GITHUB(JwtClaims.AUTH_METHOD_SOCIAL),
        LINKEDIN(JwtClaims.AUTH_METHOD_SOCIAL),
        /** A social provider this build does not know by name. */
        SOCIAL(JwtClaims.AUTH_METHOD_SOCIAL);

        private final String authMethod;

        Method(String authMethod) {
            this.authMethod = authMethod;
        }

        /** The session's auth method, as the access token and refresh-token row record it. */
        public String authMethod() {
            return authMethod;
        }

        /** The method of a social provider ({@code google}, {@code github}, ...). */
        public static Method ofProvider(String provider) {
            if (provider == null) {
                return SOCIAL;
            }
            return switch (provider.trim().toLowerCase(Locale.ROOT)) {
                case "google" -> GOOGLE;
                case "microsoft" -> MICROSOFT;
                case "github" -> GITHUB;
                case "linkedin" -> LINKEDIN;
                default -> SOCIAL;
            };
        }
    }

    private final AuditRecorder recorder;
    private final ConcurrentMap<String, Boolean> recentlyRecorded;
    private final ConcurrentMap<String, Boolean> recentlyRecordedForOrganization;

    public AuthAuditRecorder(AuditRecorder recorder, Clock clock) {
        this.recorder = recorder;
        this.recentlyRecorded = throttle(clock, THROTTLE_EVERY);
        this.recentlyRecordedForOrganization = throttle(clock, ORGANIZATION_THROTTLE_EVERY);
    }

    private static ConcurrentMap<String, Boolean> throttle(Clock clock, Duration every) {
        return Caffeine.newBuilder()
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .expireAfterWrite(every)
                .maximumSize(THROTTLE_MAX_KEYS)
                .<String, Boolean>build()
                .asMap();
    }

    /** {@code account} signed in with {@code method}; queued once the sign-in's transaction commits. */
    public void signedIn(SignInAccount account, Method method, String registrationId) {
        if (account == null) {
            return;
        }
        AuditEventRow row = asAccount(account, method, () -> build(account, AuditEventType.AUTH_SIGNED_IN,
                subject(method, registrationId, null), null));
        afterCommit(() -> recorder.recordAsync(row));
    }

    /**
     * A sign-in with {@code method} was refused for {@code reason}. With an {@code account}, the row lands
     * in its trail (internal for staff); without one, it is an internal anonymous row.
     *
     * @param organizationId for an attempt that resolved no account, the organization whose sign-in
     *                       configuration it came through (single sign-on), else null; kept on the internal
     *                       row for support, never shown to the customer
     */
    public void signInFailed(SignInAccount account, Long organizationId, Method method, String registrationId,
                             AuditReason reason) {
        AuditReason cause = reason == null ? AuditReason.INTERNAL_ERROR : reason;
        if (account != null) {
            if (throttled(AuditEventType.AUTH_SIGN_IN_FAILED, "user:" + account.userId())) {
                return;
            }
            recorder.recordFailure(asAccount(account, method, () -> build(account,
                    AuditEventType.AUTH_SIGN_IN_FAILED, subject(method, registrationId, null), cause)));
            return;
        }
        // Throttled per client address. With no address there is nothing to tell callers apart by, and one
        // shared key would let any caller's refusal hide everyone else's for a minute, so those rows are
        // not throttled; the async writer's bounded queue still caps them.
        String client = RequestContextInterceptor.getCurrentClientIp();
        if (client != null && !client.isBlank()
                && throttled(AuditEventType.AUTH_SIGN_IN_FAILED, "client:" + client)) {
            return;
        }
        // No registration id either: on an attempt that matched no configuration it is what the caller sent.
        recorder.recordFailure(AuditEvents.platformOnlyFailure(AuditEventType.AUTH_SIGN_IN_FAILED,
                subject(method, null, organizationId), cause));
    }

    /** {@link #signInFailed} for a failure the sign-in flow threw: its reason and account from its type only. */
    public void signInFailed(Throwable failure, Long organizationId, Method method, String registrationId) {
        signInFailed(SignInFailures.accountOf(failure), organizationId, method, registrationId,
                SignInFailures.reasonOf(failure));
    }

    /**
     * {@code account}'s password sign-in was just locked after {@code attempts} failed ones. Every lockout
     * counts in {@value #LOCKOUTS_METRIC} by {@code staff} and is an {@code auth.account_locked} row written
     * by CertPing, queued at once (a failed sign-in runs in no transaction). A customer account's row lands
     * in its organization's trail. A staff account has no customer trail, so its row is internal
     * ({@link AuditEvents#platformOnly}), a durable record for support; a locked staff account is someone
     * trying platform credentials, so it is also an ERROR log line to alert on.
     */
    public void accountLocked(SignInAccount account, int attempts) {
        if (account == null) {
            return;
        }
        Metrics.counter(LOCKOUTS_METRIC, "staff", Boolean.toString(account.staff())).increment();
        if (account.staff()) {
            log.error("[Security] Staff account {} locked after {} failed password sign-ins",
                    account.userId(), attempts);
        }
        AuditSubject subject = AuditSubject.builder()
                .organizationId(account.organizationId())
                .resourceId((long) account.userId())
                .resourceRef(Integer.toString(account.userId()))
                .attributes(Map.of("attempts", Integer.toString(attempts)))
                .build();
        try (AuditScope scope = AuditScope.system(LOCKOUT_JOB, account.organizationId())) {
            recorder.recordAsync(account.staff()
                    ? AuditEvents.platformOnly(AuditEventType.AUTH_ACCOUNT_LOCKED, subject)
                    : AuditEvents.success(AuditEventType.AUTH_ACCOUNT_LOCKED, subject));
        }
    }

    /**
     * A single sign-on attempt failed: {@link #signInFailed} and, when no member was matched but the attempt
     * came through {@code organizationId}'s configuration, a row in that organization's trail.
     *
     * @param organizationId the organization of the configuration the attempt came through, found by its
     *                       registration id; null when none was found
     * @param registrationId that configuration's registration id; null when none was found (an id the caller
     *                       sent that matches no configuration is never stored)
     */
    public void ssoSignInFailed(SignInAccount account, Long organizationId, Method method, String registrationId,
                                AuditReason reason) {
        signInFailed(account, organizationId, method, registrationId, reason);
        if (account == null && organizationId != null) {
            ssoFailedInOrganizationTrail(organizationId, method, registrationId,
                    reason == null ? AuditReason.INTERNAL_ERROR : reason);
        }
    }

    /** {@link #ssoSignInFailed} for a failure the single sign-on flow threw: reason and account from its type. */
    public void ssoSignInFailed(Throwable failure, Long organizationId, Method method, String registrationId) {
        ssoSignInFailed(SignInFailures.accountOf(failure), organizationId, method, registrationId,
                SignInFailures.reasonOf(failure));
    }

    private void ssoFailedInOrganizationTrail(long organizationId, Method method, String registrationId,
                                              AuditReason reason) {
        if (recentlyRecordedForOrganization.putIfAbsent("org:" + organizationId + "|" + reason.code(),
                Boolean.TRUE) != null) {
            Metrics.counter(THROTTLED_METRIC, "event", AuditEventType.AUTH_SIGN_IN_FAILED.key()).increment();
            return;
        }
        AuditEventRow row;
        try (AuditScope scope = AuditScope.anonymous(organizationId)) {
            row = AuditEvents.failure(AuditEventType.AUTH_SIGN_IN_FAILED,
                    subject(method, registrationId, organizationId), reason);
        }
        recorder.recordFailure(row.toBuilder().actorLabel(AuditDisplayNames.SOMEONE).ipAddress(null).userAgent(null)
                .build());
    }

    /** {@code account} signed out; queued at once (sign-out runs in no transaction). */
    public void signedOut(SignInAccount account, String authMethod) {
        if (account == null) {
            return;
        }
        recorder.recordAsync(asAccount(account, authMethod,
                () -> build(account, AuditEventType.AUTH_SIGNED_OUT, AuditSubject.NONE, null)));
    }

    /** {@code account} changed its password, in the change's transaction (required). */
    public void passwordChanged(SignInAccount account) {
        recorder.record(asAccount(account, (String) null,
                () -> build(account, AuditEventType.AUTH_PASSWORD_CHANGED, AuditSubject.NONE, null)));
    }

    /** {@code account}'s password change was refused: the current password it gave was wrong. */
    public void passwordChangeRefused(SignInAccount account) {
        if (throttled(AuditEventType.AUTH_PASSWORD_CHANGED, "user:" + account.userId())) {
            return;
        }
        recorder.recordFailure(asAccount(account, (String) null,
                () -> build(account, AuditEventType.AUTH_PASSWORD_CHANGED, AuditSubject.NONE, INVALID_CREDENTIALS)));
    }

    /** {@code account} confirmed a TOTP enrollment, in the enrollment's transaction (required). */
    public void mfaEnabled(SignInAccount account) {
        recorder.record(asAccount(account, (String) null,
                () -> build(account, AuditEventType.AUTH_MFA_ENABLED, AuditSubject.NONE, null)));
    }

    /** {@code account} turned its second factor off, in the change's transaction (required). */
    public void mfaDisabled(SignInAccount account) {
        recorder.record(asAccount(account, (String) null,
                () -> build(account, AuditEventType.AUTH_MFA_DISABLED, AuditSubject.NONE, null)));
    }

    /** A password reset email was sent to {@code account}; queued at once, so the answer never depends on it. */
    public void passwordResetRequested(SignInAccount account) {
        if (throttled(AuditEventType.AUTH_PASSWORD_RESET_REQUESTED, "user:" + account.userId())) {
            return;
        }
        recorder.recordAsync(asAccount(account, JwtClaims.AUTH_METHOD_LOCAL,
                () -> build(account, AuditEventType.AUTH_PASSWORD_RESET_REQUESTED, AuditSubject.NONE, null)));
    }

    /** {@code account} set a new password with an emailed link, in the reset's transaction (required). */
    public void passwordResetCompleted(SignInAccount account) {
        recorder.record(asAccount(account, JwtClaims.AUTH_METHOD_LOCAL,
                () -> build(account, AuditEventType.AUTH_PASSWORD_RESET_COMPLETED, AuditSubject.NONE, null)));
    }

    private static AuditEventRow build(SignInAccount account, AuditEventType type, AuditSubject subject,
                                       AuditReason failure) {
        if (account.staff()) {
            return failure == null ? AuditEvents.platformOnly(type, subject)
                    : AuditEvents.platformOnlyFailure(type, subject, failure);
        }
        return failure == null ? AuditEvents.success(type, subject) : AuditEvents.failure(type, subject, failure);
    }

    private static AuditEventRow asAccount(SignInAccount account, Method method, Supplier<AuditEventRow> row) {
        return asAccount(account, method == null ? null : method.authMethod(), row);
    }

    private static AuditEventRow asAccount(SignInAccount account, String authMethod, Supplier<AuditEventRow> row) {
        try (AuditScope scope = AuditScope.user(account.userId(), account.organizationId(), authMethod,
                account.superAdmin())) {
            return row.get();
        }
    }

    private static AuditSubject subject(Method method, String registrationId, Long organizationId) {
        Map<String, String> attributes = new LinkedHashMap<>();
        if (method != null) {
            attributes.put("method", method.name());
        }
        if (registrationId != null && !registrationId.isBlank()) {
            attributes.put("registrationId", registrationId);
        }
        return AuditSubject.builder().organizationId(organizationId).attributes(attributes).build();
    }

    /** Whether a row for {@code key} was already written this minute; counts the one held back. */
    private boolean throttled(AuditEventType type, String key) {
        if (recentlyRecorded.putIfAbsent(type.key() + "|" + key, Boolean.TRUE) == null) {
            return false;
        }
        Metrics.counter(THROTTLED_METRIC, "event", type.key()).increment();
        return true;
    }

    /** Runs {@code write} once the current transaction commits, or now when there is none; never on rollback. */
    private static void afterCommit(Runnable write) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            write.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == STATUS_COMMITTED) {
                    write.run();
                }
            }
        });
    }
}
