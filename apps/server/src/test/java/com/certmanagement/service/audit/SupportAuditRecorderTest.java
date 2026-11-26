// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditContext;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.incidents.domain.Incident;
import com.certmanagement.support.incidents.domain.IncidentCreationSource;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationAuditAction;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The integration rows as they are stored: a member's integration changes carry the member; what CertPing posts or
 * raises on its own is CertPing's row; and no row holds a secret or a message.
 */
class SupportAuditRecorderTest {

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final MovableClock clock = new MovableClock();
    private final SupportAuditRecorder support = new SupportAuditRecorder(recorder, clock);

    /** A clock the test moves. */
    static final class MovableClock extends java.time.Clock {
        private java.time.Instant now = java.time.Instant.parse("2026-10-08T09:00:00Z");

        void advance(java.time.Duration by) {
            now = now.plus(by);
        }

        @Override public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
        @Override public java.time.Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public java.time.Instant instant() { return now; }
    }

    @BeforeEach
    void inAMembersRequest() {
        GatewayRequestContext.set(7, "42", "req-1", "owner@acme.test");
        RequestContextInterceptor.setCurrentRequestId("req-1");
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
        RequestContextHolder.resetRequestAttributes();
        RequestContextInterceptor.clearContext();
    }

    @Test
    void integrationChangesCarryTheMember() {
        Integration slack = new Integration(42L, IntegrationProvider.SLACK, Map.of("channel", "#ops"),
                Map.of("webhook_url", "integration-42-slack-webhook-url"), 7L);
        ReflectionTestUtils.setField(slack, "id", 11L);

        support.integrationChanged(IntegrationAuditAction.CREATED, slack);
        support.integrationChanged(IntegrationAuditAction.UPDATED, slack);
        support.integrationChanged(IntegrationAuditAction.DELETED, slack);

        List<AuditEventRow> rows = recorded();
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly("Added the Slack integration",
                "Changed the Slack integration", "Removed the Slack integration");
        assertThat(rows).allSatisfy(row -> {
            assertThat(row.actorUserId()).isEqualTo(7);
            assertThat(row.resourceRef()).isEqualTo("11");
            assertThat(row.featureKey()).as("integrations are core").isNull();
            assertThat(row.toString()).doesNotContain("webhook").doesNotContain("#ops");
        });
    }

    @Test
    void anUndeliveredNotificationIsCertPingsAsyncFailureRowWithASafeReason() {
        support.integrationNotifyFailed(42L, IntegrationProvider.SLACK, "CERT_RENEWAL_FAILED",
                new ApiException(502, "INTEGRATION_NOTIFICATION_DELIVERY_FAILED",
                        "POST https://hooks.slack.com/services/T0/B0/xyz failed"));
        support.integrationNotifyFailed(43L, IntegrationProvider.TEAMS, "not a code: hooks.slack.com",
                new IllegalStateException("x"));

        ArgumentCaptor<AuditEventRow> failed = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, org.mockito.Mockito.times(2)).recordFailure(failed.capture());
        verify(recorder, never()).record(org.mockito.ArgumentMatchers.any());
        verify(recorder, never()).recordAsync(org.mockito.ArgumentMatchers.any());

        AuditEventRow failure = failed.getAllValues().get(0);
        assertThat(failure.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(failure.errorCode()).isEqualTo("INTEGRATION_DELIVERY_FAILED");
        assertThat(failure.summary()).isEqualTo("Could not send a notification to Slack");
        assertThat(failure.details().attributes()).containsExactly(Map.entry("notification", "CERT_RENEWAL_FAILED"));
        assertThat(failed.getAllValues().get(1).details().attributes()).as("free text never becomes an attribute")
                .isEmpty();
        assertThat(failed.getAllValues()).allSatisfy(row -> {
            assertThat(row.actorType()).isEqualTo(AuditActorType.SYSTEM);
            assertThat(row.actorJob()).isEqualTo(SupportAuditRecorder.DISPATCH_JOB);
            assertThat(row.actorLabel()).isEqualTo(AuditContext.SYSTEM_LABEL);
            assertThat(row.ipAddress()).isNull();
            assertThat(row.toString()).doesNotContain("hooks.slack.com");
        });
    }

    /** A broken webhook fails every notification: one row per integration and reason every 15 minutes says so. */
    @Test
    void undeliveredNotificationsAreThrottledPerIntegrationAndReason() {
        io.micrometer.core.instrument.simple.SimpleMeterRegistry metrics =
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
        io.micrometer.core.instrument.Metrics.addRegistry(metrics);
        try {
            ApiException down = new ApiException(502, "INTEGRATION_NOTIFICATION_DELIVERY_FAILED", "down");
            for (int i = 0; i < 40; i++) {
                support.integrationNotifyFailed(42L, IntegrationProvider.SLACK, "CERT_RENEWAL_FAILED", down);
                clock.advance(java.time.Duration.ofSeconds(20));
            }
            // Another integration, another organization, or another reason is its own row at once.
            support.integrationNotifyFailed(42L, IntegrationProvider.TEAMS, "CERT_RENEWAL_FAILED", down);
            support.integrationNotifyFailed(43L, IntegrationProvider.SLACK, "CERT_RENEWAL_FAILED", down);
            support.integrationNotifyFailed(42L, IntegrationProvider.SLACK, "CERT_RENEWAL_FAILED",
                    new ApiException(429, "RATE_LIMITED", "slow down"));

            // 40 attempts over 13 minutes: one row; then three new keys.
            verify(recorder, org.mockito.Mockito.times(4)).recordFailure(org.mockito.ArgumentMatchers.any());
            assertThat(metrics.get("certping.audit.throttled").tag("event", "integration.notified").counter().count())
                    .isEqualTo(39.0);

            clock.advance(java.time.Duration.ofMinutes(3));
            support.integrationNotifyFailed(42L, IntegrationProvider.SLACK, "CERT_RENEWAL_FAILED", down);
            verify(recorder, org.mockito.Mockito.times(5)).recordFailure(org.mockito.ArgumentMatchers.any());
        } finally {
            io.micrometer.core.instrument.Metrics.removeRegistry(metrics);
        }
    }

    @Test
    void anIncidentIsTheMembersOrCertPingsByWhoRaisedIt() {
        support.incidentTriggered(incident(IncidentCreationSource.PUBLIC_API));
        support.incidentTriggered(incident(IncidentCreationSource.INTERNAL_API));

        List<AuditEventRow> rows = recorded();
        assertThat(rows).extracting(AuditEventRow::summary).containsOnly("Raised an incident in PagerDuty");
        assertThat(rows).extracting(AuditEventRow::actorType).containsExactly(AuditActorType.USER,
                AuditActorType.SYSTEM);
        assertThat(rows.get(1).actorJob()).isEqualTo(SupportAuditRecorder.DISPATCH_JOB);
        assertThat(rows.get(0).details().attributes()).containsEntry("source", "PUBLIC_API")
                .containsEntry("incidentReference", "INC-1");
        // The member's incident commits with their request; CertPing's own is isolated from it.
        verify(recorder).record(org.mockito.ArgumentMatchers.any());
        verify(recorder).recordIsolated(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void onlyCertPingsOwnFailedIncidentIsRecordedHere() {
        support.incidentFailed(42L, IncidentCreationSource.PUBLIC_API, IntegrationProvider.PAGERDUTY,
                new ApiException(404, "INTEGRATION_NOT_FOUND", "missing"));
        verify(recorder, never()).recordFailure(org.mockito.ArgumentMatchers.any());

        support.incidentFailed(42L, IncidentCreationSource.INTERNAL_API, IntegrationProvider.SERVICENOW_ITSM,
                new IllegalStateException("connect to acme.service-now.com refused"));
        ArgumentCaptor<AuditEventRow> failed = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder).recordFailure(failed.capture());
        assertThat(failed.getValue().summary()).isEqualTo("Could not raise an incident in ServiceNow");
        assertThat(failed.getValue().errorCode()).isEqualTo("INTEGRATION_DELIVERY_FAILED");
        assertThat(failed.getValue().toString()).doesNotContain("service-now.com");
    }


    @Test
    void aDeliveryFailureReasonComesFromTheTypeAndStatusOnly() {
        assertThat(SupportAuditRecorder.deliveryReason(new ApiException(504, "X_TIMEOUT", "t")))
                .isEqualTo(SupportAuditRecorder.INTEGRATION_DELIVERY_FAILED);
        assertThat(SupportAuditRecorder.deliveryReason(new ApiException(404, "INTEGRATION_NOT_FOUND", "gone")))
                .isEqualTo(AuditReason.of("NOT_FOUND"));
        assertThat(SupportAuditRecorder.deliveryReason(new RuntimeException("jdbc:postgresql://db")))
                .isEqualTo(SupportAuditRecorder.INTEGRATION_DELIVERY_FAILED);
    }

    private Incident incident(IncidentCreationSource source) {
        Incident incident = new Incident(42L, source == IncidentCreationSource.PUBLIC_API ? 7L : null, source,
                IntegrationProvider.PAGERDUTY, null, "summary with customer text", "ext", "INC-1",
                "https://incidents.test/1");
        ReflectionTestUtils.setField(incident, "id", 33L);
        return incident;
    }

    /** Every row written in the change's transaction, by {@code record} or {@code recordIsolated}. */
    private List<AuditEventRow> recorded() {
        List<AuditEventRow> rows = org.mockito.Mockito.mockingDetails(recorder).getInvocations().stream()
                .filter(call -> call.getMethod().getName().equals("record")
                        || call.getMethod().getName().equals("recordIsolated"))
                .map(call -> (AuditEventRow) call.getArgument(0)).toList();
        assertThat(rows).as("rows written in the change's transaction").isNotEmpty();
        return rows;
    }
}
