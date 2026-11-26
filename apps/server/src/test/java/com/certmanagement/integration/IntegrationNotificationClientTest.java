// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.audit.OrganizationAuditRecorder;
import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.service.notification.NotificationPreferenceService;
import com.certmanagement.support.incidents.api.model.InternalPagerDutyIncidentPayload;
import com.certmanagement.support.incidents.api.model.InternalServiceNowIncidentPayload;
import com.certmanagement.support.incidents.application.IncidentService;
import com.certmanagement.support.integrations.api.model.IntegrationResponse;
import com.certmanagement.support.integrations.api.model.SendIntegrationNotificationRequest;
import com.certmanagement.support.integrations.application.IntegrationDeliveryGate;
import com.certmanagement.support.integrations.application.IntegrationNotificationService;
import com.certmanagement.support.integrations.application.IntegrationService;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.domain.IntegrationStatus;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class IntegrationNotificationClientTest {

    private static final long TIMEOUT_MS = 3000;

    @Mock
    private IntegrationService integrationService;
    @Mock
    private IntegrationNotificationService integrationNotificationService;
    @Mock
    private IncidentService incidentService;

    @Mock
    private SupportAuditRecorder supportAudit;
    @Mock
    private OrganizationRepository organizations;
    @Mock
    private OrganizationAuditRecorder organizationAudit;

    private IntegrationNotificationClient client;

    @Mock
    private com.certmanagement.service.FeatureFlagService featureFlags;
    private final io.micrometer.core.instrument.simple.SimpleMeterRegistry meters =
            new io.micrometer.core.instrument.simple.SimpleMeterRegistry();

    @BeforeEach
    void setUp() {
        org.mockito.Mockito.lenient().when(featureFlags.isEnabled(
                org.mockito.ArgumentMatchers.eq(com.certmanagement.constants.FeatureFlags.INTEGRATIONS),
                org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);
        org.mockito.Mockito.lenient().when(featureFlags.isEnabled(
                org.mockito.ArgumentMatchers.eq(com.certmanagement.constants.FeatureFlags.NOTIFICATION_PREFERENCES),
                org.mockito.ArgumentMatchers.anyLong())).thenReturn(false);
        client = new IntegrationNotificationClient(
                integrationService, integrationNotificationService, incidentService,
                new IntegrationDeliveryGate(featureFlags, meters),
                new NotificationPreferenceService(featureFlags, organizations, organizationAudit, meters),
                supportAudit);
        ReflectionTestUtils.setField(client, "dashboardBaseUrl", "https://app.example.com/dashboard");
    }

    private IntegrationResponse integration(IntegrationProvider provider, IntegrationStatus status) {
        return new IntegrationResponse(1L, provider, status, Instant.now(), Instant.now(), null);
    }

    @Test
    void dispatch_unparseableOrgId_skips() {
        client.dispatch("not-a-number", "CERT_ISSUANCE_SUCCESS", "xref", Map.of());
        verify(integrationService, never()).listIntegrationsForOrganization(anyLong());
    }

    @Test
    void dispatch_slackAndTeams_sendsNotifications() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(
                        integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE),
                        integration(IntegrationProvider.TEAMS, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1",
                Map.of("domain", "api.example.com", "caProvider", "LetsEncrypt"));

        ArgumentCaptor<SendIntegrationNotificationRequest> captor =
                ArgumentCaptor.forClass(SendIntegrationNotificationRequest.class);
        verify(integrationNotificationService, timeout(TIMEOUT_MS).times(2)).sendNotification(captor.capture());

        List<SendIntegrationNotificationRequest> requests = captor.getAllValues();
        assertThat(requests).extracting(SendIntegrationNotificationRequest::provider)
                .containsExactlyInAnyOrder(IntegrationProvider.SLACK, IntegrationProvider.TEAMS);
        assertThat(requests.get(0).data().title()).contains("Certificate Issued");
        assertThat(requests.get(0).data().linkUrl()).isEqualTo("https://app.example.com/cert-manager/manage/CERT-1");
        // A delivered notification is the integration's delivery history, never an audit row.
        verify(supportAudit, org.mockito.Mockito.after(200).never()).integrationNotifyFailed(any(), any(), any(),
                any());
    }

    @Test
    void dispatch_integrationsOff_skipsEveryRecipientAndCountsIt() {
        when(featureFlags.isEnabled(com.certmanagement.constants.FeatureFlags.INTEGRATIONS, 42L)).thenReturn(false);
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(
                        integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE),
                        integration(IntegrationProvider.PAGERDUTY, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_RENEWAL_FAILED", "CERT-1", Map.of("domain", "x.com"));

        verify(featureFlags, timeout(TIMEOUT_MS)).isEnabled(com.certmanagement.constants.FeatureFlags.INTEGRATIONS, 42L);
        verify(integrationNotificationService, org.mockito.Mockito.after(200).never()).sendNotification(any());
        verify(incidentService, never()).createInternalPagerDutyIncident(anyLong(), any());
        assertThat(meters.counter("certping.integrations.delivery_skipped", "kind", "SLACK").count()).isEqualTo(1);
        assertThat(meters.counter("certping.integrations.delivery_skipped", "kind", "PAGERDUTY").count()).isEqualTo(1);
    }

    @Test
    void noActionAnOrganizationCanTurnOffOpensAnIncident() {
        assertThat(java.util.Arrays.stream(com.certmanagement.service.notification.NotificationCategory.values())
                .flatMap(category -> category.actions().stream()))
                .doesNotContainAnyElementsOf(IntegrationNotificationClient.FAILURE_ACTIONS);
    }

    @Test
    void dispatch_aCategoryTheOrganizationTurnedOff_postsNothingAndCountsIt() {
        when(featureFlags.isEnabled(FeatureFlags.NOTIFICATION_PREFERENCES, 42L)).thenReturn(true);
        when(organizations.findMutedNotificationCategories(42L)).thenReturn(java.util.Optional.of("CERTIFICATE_ACTIVITY"));
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE),
                        integration(IntegrationProvider.TEAMS, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_RENEWAL_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(organizations, timeout(TIMEOUT_MS)).findMutedNotificationCategories(42L);
        verify(integrationNotificationService, org.mockito.Mockito.after(200).never()).sendNotification(any());
        assertThat(meters.counter("certping.notifications.suppressed", "channel", "integration",
                "category", "CERTIFICATE_ACTIVITY").count()).isEqualTo(1);
    }

    @Test
    void dispatch_aFailureIsPostedAndPagedWhateverTheOrganizationTurnedOff() {
        lenient().when(featureFlags.isEnabled(FeatureFlags.NOTIFICATION_PREFERENCES, 42L)).thenReturn(true);
        lenient().when(organizations.findMutedNotificationCategories(42L))
                .thenReturn(java.util.Optional.of("CERTIFICATE_ACTIVITY,REPORTS"));
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE),
                        integration(IntegrationProvider.PAGERDUTY, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_RENEWAL_FAILED", "CERT-1", Map.of("domain", "x.com"));

        verify(integrationNotificationService, timeout(TIMEOUT_MS)).sendNotification(any());
        verify(incidentService, timeout(TIMEOUT_MS)).createInternalPagerDutyIncident(eq(42L), any());
        verify(organizations, never()).findMutedNotificationCategories(anyLong());
    }

    @Test
    void dispatch_aCategoryTurnedOffWhileNotificationSettingsAreOff_isPosted() {
        when(featureFlags.isEnabled(FeatureFlags.NOTIFICATION_PREFERENCES, 42L)).thenReturn(false);
        lenient().when(organizations.findMutedNotificationCategories(42L))
                .thenReturn(java.util.Optional.of("CERTIFICATE_ACTIVITY"));
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_RENEWAL_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(integrationNotificationService, timeout(TIMEOUT_MS)).sendNotification(any());
    }

    @Test
    void dispatch_integrationsFlagUnreadable_stillDelivers() {
        when(featureFlags.isEnabled(com.certmanagement.constants.FeatureFlags.INTEGRATIONS, 42L))
                .thenThrow(new IllegalStateException("flag store down"));
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(integrationNotificationService, timeout(TIMEOUT_MS)).sendNotification(any());
    }

    @Test
    void dispatch_inactiveIntegrationsFilteredOut() {
        lenient().when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.DISABLED)));

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        // Wait for the discovery call, then confirm nothing was sent.
        verify(integrationService, timeout(TIMEOUT_MS)).listIntegrationsForOrganization(42L);
        verify(integrationNotificationService, never()).sendNotification(any());
    }

    @Test
    void dispatch_failureAction_triggersPagerDutyAndServiceNow() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(
                        integration(IntegrationProvider.PAGERDUTY, IntegrationStatus.ACTIVE),
                        integration(IntegrationProvider.SERVICENOW_ITSM, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_ISSUANCE_FAILED", "CERT-9",
                Map.of("domain", "fail.example.com", "errorCode", "E1", "errorMessage", "boom"));

        ArgumentCaptor<InternalPagerDutyIncidentPayload> pdCaptor =
                ArgumentCaptor.forClass(InternalPagerDutyIncidentPayload.class);
        verify(incidentService, timeout(TIMEOUT_MS)).createInternalPagerDutyIncident(eq(42L), pdCaptor.capture());
        assertThat(pdCaptor.getValue().title()).contains("Certificate Issuance Failed");
        assertThat(pdCaptor.getValue().severity().name()).isEqualTo("ERROR");

        ArgumentCaptor<InternalServiceNowIncidentPayload> snCaptor =
                ArgumentCaptor.forClass(InternalServiceNowIncidentPayload.class);
        verify(incidentService, timeout(TIMEOUT_MS)).createInternalServiceNowIncident(eq(42L), snCaptor.capture());
        assertThat(snCaptor.getValue().impact().name()).isEqualTo("HIGH");
        assertThat(snCaptor.getValue().correlationDisplay()).isEqualTo("CERT-9");
    }

    @Test
    void dispatch_domainInfoAction_doesNotTriggerIncidents() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.PAGERDUTY, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "DOMAIN_EXPIRING_SOON", null, Map.of("domainName", "example.com", "daysRemaining", 7));

        verify(integrationService, timeout(TIMEOUT_MS)).listIntegrationsForOrganization(42L);
        verify(incidentService, never()).createInternalPagerDutyIncident(anyLong(), any());
    }

    @Test
    void dispatch_failureAction_pagerDutyNotActive_skipsIncident() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_RENEWAL_FAILED", "CERT-9", Map.of("domain", "x.com"));

        verify(integrationNotificationService, timeout(TIMEOUT_MS)).sendNotification(any());
        verify(incidentService, timeout(500).times(0)).createInternalPagerDutyIncident(anyLong(), any());
    }

    @Test
    void dispatch_successActionDoesNotTriggerIncidents() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.PAGERDUTY, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(integrationService, timeout(TIMEOUT_MS)).listIntegrationsForOrganization(42L);
        verify(incidentService, never()).createInternalPagerDutyIncident(anyLong(), any());
    }

    @Test
    void dispatch_listThrows_abortsGracefully() {
        lenient().when(integrationService.listIntegrationsForOrganization(42L))
                .thenThrow(new RuntimeException("db down"));

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(integrationService, timeout(TIMEOUT_MS)).listIntegrationsForOrganization(42L);
        verify(integrationNotificationService, never()).sendNotification(any());
    }

    @Test
    void dispatch_nullIntegrationList_skips() {
        lenient().when(integrationService.listIntegrationsForOrganization(42L)).thenReturn(null);

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(integrationService, timeout(TIMEOUT_MS)).listIntegrationsForOrganization(42L);
        verify(integrationNotificationService, never()).sendNotification(any());
    }

    @Test
    void dispatch_deploymentEvent_buildsDeploymentLink() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_DEPLOYMENT_SUCCESS", "CERT-1",
                Map.of("domain", "x.com", "userDomainCertId", "udc-5", "deploymentId", "dep-7"));

        ArgumentCaptor<SendIntegrationNotificationRequest> captor =
                ArgumentCaptor.forClass(SendIntegrationNotificationRequest.class);
        verify(integrationNotificationService, timeout(TIMEOUT_MS)).sendNotification(captor.capture());
        assertThat(captor.getValue().data().linkUrl())
                .isEqualTo("https://app.example.com/cert-manager/deployments/udc-5/dep-7");
    }

    @Test
    void dispatch_explicitDashboardUrlWins() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE)));

        client.dispatch("42", "CERT_EXPIRY_ALERT", "CERT-1",
                Map.of("domain", "x.com", "daysRemaining", "5", "dashboardUrl", "https://override.example.com/x"));

        ArgumentCaptor<SendIntegrationNotificationRequest> captor =
                ArgumentCaptor.forClass(SendIntegrationNotificationRequest.class);
        verify(integrationNotificationService, timeout(TIMEOUT_MS)).sendNotification(captor.capture());
        assertThat(captor.getValue().data().linkUrl()).isEqualTo("https://override.example.com/x");
        assertThat(captor.getValue().data().message()).contains("expires in 5 day(s)");
    }

    @Test
    void dispatch_notificationServiceThrows_swallowed() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE)));
        // notification failure must be swallowed (non-fatal) — no exception escapes the async task
        org.mockito.Mockito.doThrow(new RuntimeException("send failed"))
                .when(integrationNotificationService).sendNotification(any());

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(integrationNotificationService, timeout(TIMEOUT_MS)).sendNotification(any());
        verify(supportAudit, timeout(TIMEOUT_MS)).integrationNotifyFailed(eq(42L), eq(IntegrationProvider.SLACK),
                eq("CERT_ISSUANCE_SUCCESS"), any(RuntimeException.class));
    }

    @Test
    void dispatch_auditRowThatCannotBeRecorded_neverBreaksTheDispatch() {
        when(integrationService.listIntegrationsForOrganization(42L))
                .thenReturn(List.of(integration(IntegrationProvider.SLACK, IntegrationStatus.ACTIVE)));
        org.mockito.Mockito.doThrow(new RuntimeException("send failed"))
                .when(integrationNotificationService).sendNotification(any());
        org.mockito.Mockito.doThrow(new IllegalStateException("queue closed"))
                .when(supportAudit).integrationNotifyFailed(any(), any(), any(), any());

        client.dispatch("42", "CERT_ISSUANCE_SUCCESS", "CERT-1", Map.of("domain", "x.com"));

        verify(supportAudit, timeout(TIMEOUT_MS)).integrationNotifyFailed(eq(42L), eq(IntegrationProvider.SLACK),
                eq("CERT_ISSUANCE_SUCCESS"), any(RuntimeException.class));
    }
}
