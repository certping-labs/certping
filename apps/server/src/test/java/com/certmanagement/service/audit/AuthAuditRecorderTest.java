// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.SignInAccount;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * The sign-in events as rows: whose trail they land in, who the actor is, where the request came from,
 * the reason a refusal carries, the throttle, and when a sign-in is handed to the writer.
 */
class AuthAuditRecorderTest {

    private static final SignInAccount ALICE = new SignInAccount(7, 42L, false);
    private static final SignInAccount STAFF = new SignInAccount(1, null, true);

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-07T12:00:00Z"));
    private final AuthAuditRecorder auth = new AuthAuditRecorder(recorder, clock);
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();

    @BeforeEach
    void fromABrowser() {
        Metrics.addRegistry(metrics);
        RequestContextInterceptor.setCurrentRequestId("req-login");
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
        request.addHeader("User-Agent", "Mozilla/5.0 test");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void clear() {
        Metrics.removeRegistry(metrics);
        RequestContextInterceptor.clearContext();
        RequestContextHolder.resetRequestAttributes();
        GatewayRequestContext.clear();
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void aSignInLandsInTheAccountsTrailWithTheAccountAsActorAndTheRequestsClient() {
        auth.signedIn(ALICE, AuthAuditRecorder.Method.PASSWORD, null);

        AuditEventRow row = queued();
        assertThat(row.event()).isEqualTo("auth.signed_in");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.category()).isEqualTo("AUTHENTICATION");
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.actorType()).isEqualTo(AuditActorType.USER);
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.authMethod()).isEqualTo("LOCAL");
        assertThat(row.actorStaff()).isFalse();
        assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(row.summary()).isEqualTo("Signed in with a password");
        assertThat(row.ipAddress()).isEqualTo("203.0.113.9");
        assertThat(row.userAgent()).isEqualTo("Mozilla/5.0 test");
        assertThat(row.requestId()).isEqualTo("req-login");
    }

    @Test
    void eachMethodReadsInWords() {
        auth.signedIn(ALICE, AuthAuditRecorder.Method.OIDC, "org-42-oidc");
        auth.signedIn(ALICE, AuthAuditRecorder.Method.ofProvider("google"), null);
        auth.signedIn(ALICE, AuthAuditRecorder.Method.ofProvider("github"), null);

        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, times(3)).recordAsync(rows.capture());
        assertThat(rows.getAllValues()).extracting(AuditEventRow::summary).containsExactly(
                "Signed in with single sign-on", "Signed in with Google", "Signed in with GitHub");
        assertThat(rows.getAllValues().get(0).details().attributes())
                .containsEntry("method", "OIDC").containsEntry("registrationId", "org-42-oidc");
        assertThat(rows.getAllValues().get(0).authMethod()).isEqualTo("SSO");
        assertThat(rows.getAllValues().get(1).authMethod()).isEqualTo("SOCIAL");
    }

    @Test
    void theActorIsTheAccountEvenWhenTheRequestCarriesAnotherUsersToken() {
        GatewayRequestContext.set(99, "5", "req-login", "someone@else.test");

        auth.signedIn(ALICE, AuthAuditRecorder.Method.PASSWORD, null);

        assertThat(queued().actorUserId()).isEqualTo(7);
        assertThat(queued().organizationId()).isEqualTo(42L);
    }

    @Test
    void aStaffSignInIsInternalAndMarkedAsStaff() {
        auth.signedIn(STAFF, AuthAuditRecorder.Method.PASSWORD, null);

        AuditEventRow row = queued();
        assertThat(row.event()).isEqualTo("auth.signed_in");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.organizationId()).isNull();
        assertThat(row.actorUserId()).isEqualTo(1);
        assertThat(row.actorStaff()).isTrue();
    }

    @Test
    void aSignInIsQueuedOnlyOnceItsTransactionCommits() {
        TransactionSynchronizationManager.initSynchronization();
        auth.signedIn(ALICE, AuthAuditRecorder.Method.PASSWORD, null);
        verifyNoInteractions(recorder);

        complete(TransactionSynchronization.STATUS_ROLLED_BACK);
        verifyNoInteractions(recorder);

        TransactionSynchronizationManager.initSynchronization();
        auth.signedIn(ALICE, AuthAuditRecorder.Method.PASSWORD, null);
        complete(TransactionSynchronization.STATUS_COMMITTED);
        verify(recorder).recordAsync(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"INVALID_CREDENTIALS", "ACCOUNT_DISABLED", "ACCOUNT_LOCKED", "ORGANIZATION_SUSPENDED",
            "SSO_REJECTED", "SSO_MISCONFIGURED", "SIGN_IN_METHOD_NOT_ALLOWED"})
    void aRefusedSignInForAKnownAccountLandsInItsTrailWithTheReason(String code) {
        auth.signInFailed(ALICE, null, AuthAuditRecorder.Method.PASSWORD, null, AuditReason.of(code));

        AuditEventRow row = failed();
        assertThat(row.event()).isEqualTo("auth.sign_in_failed");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(row.errorCode()).isEqualTo(code);
        assertThat(row.summary()).isEqualTo("Could not sign in with a password");
        assertThat(AuditReason.of(code).message(null)).doesNotStartWith("Something went wrong");
    }

    @Test
    void aRefusalForAnUnknownIdentifierIsAnInternalAnonymousRowNamingNoOne() {
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, AuditReason.of("INVALID_CREDENTIALS"));

        AuditEventRow row = failed();
        assertThat(row.event()).isEqualTo("auth.sign_in_failed");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.actorType()).isEqualTo(AuditActorType.ANONYMOUS);
        assertThat(row.actorUserId()).isNull();
        assertThat(row.organizationId()).isNull();
        assertThat(row.resourceRef()).isNull();
        assertThat(row.resourceName()).isNull();
        assertThat(row.details().attributes()).containsOnlyKeys("method");
        assertThat(row.errorCode()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(row.ipAddress()).isEqualTo("203.0.113.9");
    }

    @Test
    void anSsoRefusalWithNoAccountKeepsOnlyTheConfigurationsOrganizationOnTheInternalRow() {
        auth.signInFailed(null, 42L, AuthAuditRecorder.Method.OIDC, "org-42-oidc",
                AuditReason.of("SSO_REJECTED"));

        AuditEventRow row = failed();
        assertThat(row.visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.details().attributes()).containsOnlyKeys("method");
    }

    @Test
    void refusalsAreThrottledToOnePerAccountPerMinute() {
        AuditReason invalid = AuditReason.of("INVALID_CREDENTIALS");
        for (int i = 0; i < 5; i++) {
            auth.signInFailed(ALICE, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        }
        auth.signInFailed(new SignInAccount(8, 42L, false), null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        verify(recorder, times(2)).recordFailure(any());
        assertThat(metrics.counter("certping.audit.throttled", "event", "auth.sign_in_failed").count()).isEqualTo(4.0);

        clock.advance(Duration.ofSeconds(61));
        auth.signInFailed(ALICE, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        verify(recorder, times(3)).recordFailure(any());
    }

    @Test
    void unknownIdentifierRefusalsAreThrottledPerClientAddress() {
        AuditReason invalid = AuditReason.of("INVALID_CREDENTIALS");
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        RequestContextInterceptor.setCurrentClientIp("198.51.100.4");
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);

        verify(recorder, times(2)).recordFailure(any());
    }

    @Test
    void unknownIdentifierRefusalsWithNoClientAddressAreNotThrottledUnderOneSharedKey() {
        AuditReason invalid = AuditReason.of("INVALID_CREDENTIALS");
        RequestContextInterceptor.setCurrentClientIp(null);
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        RequestContextInterceptor.setCurrentClientIp(" ");
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        verify(recorder, times(3)).recordFailure(any());

        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        auth.signInFailed(null, null, AuthAuditRecorder.Method.PASSWORD, null, invalid);
        verify(recorder, times(4)).recordFailure(any());
        assertThat(metrics.counter("certping.audit.throttled", "event", "auth.sign_in_failed").count()).isEqualTo(1.0);
    }

    @Test
    void signingOutIsTheAccountsRow() {
        auth.signedOut(ALICE, "SSO");

        AuditEventRow row = queued();
        assertThat(row.event()).isEqualTo("auth.signed_out");
        assertThat(row.summary()).isEqualTo("Signed out");
        assertThat(row.actorUserId()).isEqualTo(7);
        assertThat(row.organizationId()).isEqualTo(42L);
        assertThat(row.authMethod()).isEqualTo("SSO");

        auth.signedOut(null, null);
        verify(recorder, times(1)).recordAsync(any());
    }

    @Test
    void aPasswordChangeIsWrittenInTheChangesTransactionAndARefusalIsQueuedAndThrottled() {
        auth.passwordChanged(ALICE);
        ArgumentCaptor<AuditEventRow> changed = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).record(changed.capture());
        assertThat(changed.getValue().event()).isEqualTo("auth.password_changed");
        assertThat(changed.getValue().summary()).isEqualTo("Changed their password");
        assertThat(changed.getValue().outcome()).isEqualTo(AuditOutcome.SUCCESS);

        auth.passwordChangeRefused(ALICE);
        auth.passwordChangeRefused(ALICE);
        AuditEventRow refused = failed();
        assertThat(refused.event()).isEqualTo("auth.password_changed");
        assertThat(refused.errorCode()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(refused.summary()).isEqualTo("Could not change their password");
    }

    @Test
    void aResetRequestIsQueuedAndThrottledAndACompletedResetIsWrittenInItsTransaction() {
        auth.passwordResetRequested(ALICE);
        auth.passwordResetRequested(ALICE);
        AuditEventRow requested = queued();
        assertThat(requested.event()).isEqualTo("auth.password_reset_requested");
        assertThat(requested.summary()).isEqualTo("Requested a password reset email");
        assertThat(requested.actorUserId()).isEqualTo(7);

        auth.passwordResetCompleted(ALICE);
        ArgumentCaptor<AuditEventRow> completed = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).record(completed.capture());
        assertThat(completed.getValue().event()).isEqualTo("auth.password_reset_completed");
        assertThat(completed.getValue().summary()).isEqualTo("Reset their password with an emailed link");
        verify(recorder, never()).recordFailure(any());
    }

    @Test
    void aStaffPasswordChangeIsInternal() {
        auth.passwordChanged(STAFF);
        ArgumentCaptor<AuditEventRow> changed = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).record(changed.capture());
        assertThat(changed.getValue().visibility()).isEqualTo(AuditVisibility.INTERNAL);
        assertThat(changed.getValue().actorStaff()).isTrue();
    }

    private AuditEventRow queued() {
        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, org.mockito.Mockito.atLeastOnce()).recordAsync(row.capture());
        return row.getAllValues().get(0);
    }

    private AuditEventRow failed() {
        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordFailure(row.capture());
        return row.getValue();
    }

    private static void complete(int status) {
        var synchronizations = TransactionSynchronizationManager.getSynchronizations();
        TransactionSynchronizationManager.clearSynchronization();
        synchronizations.forEach(s -> s.afterCompletion(status));
    }

    // ── Single sign-on failures in the organization's trail ──────────────

    @Test
    void aSingleSignOnFailureMatchingNoMemberIsAlsoWrittenIntoItsOrganizationsTrailWithoutTheClient() {
        auth.ssoSignInFailed(null, 42L, AuthAuditRecorder.Method.OIDC, "org-42-oidc",
                AuditReason.of("SSO_REJECTED"));

        java.util.List<AuditEventRow> rows = failures();
        assertThat(rows).extracting(AuditEventRow::visibility)
                .containsExactlyInAnyOrder(AuditVisibility.INTERNAL, AuditVisibility.CUSTOMER);
        AuditEventRow internal = rows.stream().filter(r -> r.visibility() == AuditVisibility.INTERNAL).findFirst()
                .orElseThrow();
        assertThat(internal.ipAddress()).as("support keeps the per-address row").isEqualTo("203.0.113.9");
        AuditEventRow customer = rows.stream().filter(r -> r.visibility() == AuditVisibility.CUSTOMER).findFirst()
                .orElseThrow();
        assertThat(customer.organizationId()).isEqualTo(42L);
        assertThat(customer.event()).isEqualTo("auth.sign_in_failed");
        assertThat(customer.summary()).isEqualTo("Could not sign in with single sign-on");
        assertThat(customer.errorCode()).isEqualTo("SSO_REJECTED");
        assertThat(customer.actorType()).isEqualTo(AuditActorType.ANONYMOUS);
        assertThat(customer.actorUserId()).isNull();
        assertThat(customer.actorLabel()).isEqualTo("Someone");
        assertThat(customer.ipAddress()).isNull();
        assertThat(customer.userAgent()).isNull();
        assertThat(customer.requestId()).as("the person signing in can quote it").isEqualTo("req-login");
        assertThat(customer.details().attributes()).containsOnly(java.util.Map.entry("method", "OIDC"),
                java.util.Map.entry("registrationId", "org-42-oidc"));
    }

    @Test
    void theOrganizationsTrailGetsOneRowPerReasonEveryFiveMinutes() {
        RequestContextInterceptor.setCurrentClientIp(null);
        for (int i = 0; i < 5; i++) {
            auth.ssoSignInFailed(null, 42L, AuthAuditRecorder.Method.OIDC, "org-42-entra-oidc",
                    AuditReason.of("SSO_REJECTED"));
        }
        auth.ssoSignInFailed(null, 42L, AuthAuditRecorder.Method.OIDC, "org-42-entra-oidc",
                AuditReason.of("SSO_MISCONFIGURED"));
        auth.ssoSignInFailed(null, 43L, AuthAuditRecorder.Method.OIDC, "org-43-entra-oidc",
                AuditReason.of("SSO_REJECTED"));
        assertThat(customerFailures()).as("per organization and reason, not per address").hasSize(3);

        clock.advance(Duration.ofMinutes(4));
        auth.ssoSignInFailed(null, 42L, AuthAuditRecorder.Method.OIDC, "org-42-entra-oidc",
                AuditReason.of("SSO_REJECTED"));
        assertThat(customerFailures()).hasSize(3);

        clock.advance(Duration.ofMinutes(2));
        auth.ssoSignInFailed(null, 42L, AuthAuditRecorder.Method.OIDC, "org-42-entra-oidc",
                AuditReason.of("SSO_REJECTED"));
        assertThat(customerFailures()).hasSize(4);
        assertThat(metrics.find("certping.audit.throttled").tag("event", "auth.sign_in_failed").counter().count())
                .isPositive();
    }

    @Test
    void aFailureForAMatchedMemberOrNoKnownConfigurationIsNotAnOrganizationRow() {
        SignInAccount member = new SignInAccount(21, 42L, false);
        auth.ssoSignInFailed(member, 42L, AuthAuditRecorder.Method.OIDC, "org-42-oidc",
                AuditReason.of("ACCOUNT_DISABLED"));
        auth.ssoSignInFailed(null, null, AuthAuditRecorder.Method.OIDC, null, AuditReason.of("SSO_REJECTED"));

        assertThat(customerFailures()).singleElement().satisfies(row -> {
            assertThat(row.actorUserId()).as("the member's own row, as before").isEqualTo(21);
            assertThat(row.actorLabel()).isNull();
        });
    }

    private java.util.List<AuditEventRow> failures() {
        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, org.mockito.Mockito.atLeast(0)).recordFailure(rows.capture());
        return rows.getAllValues();
    }

    private java.util.List<AuditEventRow> customerFailures() {
        return failures().stream().filter(row -> row.visibility() == AuditVisibility.CUSTOMER).toList();
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
