// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.DeadLetterOptions;
import com.certping.notification.config.EmailConfig;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.model.NotificationRecord;
import com.certping.notification.repository.NotificationRepository;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.task.SyncTaskExecutor;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * End to end through the notifier's own layers: a body exactly as the server publishes it
 * (ProducerEnvelopes) reaches the listener, becomes a NotificationEvent, and NotificationService picks
 * the template, subject and delivery path. That each recipient is then sent once under the key is
 * proven against Postgres in LifecycleDeliverOncePostgresTest.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LifecycleEmailRoutingTest {

    private static final List<String> ADMINS = List.of("admin1@acme.example", "admin2@acme.example");
    private static final String NOT_DEPLOYED_SUBJECT =
            "CertPing - Certificate for shop.example.com renewed — deploy it to keep it in use";

    @Mock private NotificationRepository notificationRepository;
    @Mock private EmailProvider emailProvider;
    @Mock private EmailConfig emailConfig;
    @Mock private RoleEmailMapper roleEmailMapper;
    @Mock private RecipientDelivery recipientDelivery;
    @Mock private NotificationService mockedNotificationService;
    @Mock private ScheduledRetryService scheduledRetryService;
    @Mock private UndeliveredEmailService undeliveredEmailService;
    @Mock private DeliveryTimeouts deliveryTimeouts;
    @Mock private InboundContext context;
    @Mock private InboundMessage message;

    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

    @Test
    void featurePausedGoesDeliverOnceToTheOrganizationAdminsUnderThePublishersKey() {
        NotificationEvent routed = routedDeliverOnce(ProducerEnvelopes.feature("PAUSED"), "feature-paused",
                "CertPing - Certificate discovery is paused for Acme Ltd");

        assertThat(routed.idempotencyKey()).isEqualTo(ProducerEnvelopes.featureKey("PAUSED"));
    }

    @Test
    void featureResumedGoesDeliverOnceToTheOrganizationAdmins() {
        NotificationEvent routed = routedDeliverOnce(ProducerEnvelopes.feature("RESUMED"), "feature-resumed",
                "CertPing - Certificate discovery is available again");

        assertThat(routed.idempotencyKey()).isEqualTo(ProducerEnvelopes.featureKey("RESUMED"));
    }

    @Test
    void renewedNotDeployedGoesDeliverOnceUnderItsRequestId() {
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> model = ArgumentCaptor.forClass(Map.class);

        NotificationEvent routed = routedDeliverOnce(ProducerEnvelopes.renewedNotDeployed(),
                "cert-renewed-not-deployed", NOT_DEPLOYED_SUBJECT);

        assertThat(routed.idempotencyKey()).isEqualTo(ProducerEnvelopes.NOT_DEPLOYED_KEY);
        verify(recipientDelivery).deliver(any(), any(), any(), any(), model.capture(), anyString());
        assertThat(model.getValue()).containsEntry(RenewedNotDeployedEmail.CERTIFICATE_PAGE_URL,
                "https://certping.example.com/cert-manager/manage/CERT-NEW-2");
    }

    @Test
    void renewedNotDeployedWithoutAValidKeyIsStillSentToEachAdmin() {
        Map<String, Object> details = ProducerEnvelopes.renewalDetails();
        details.put("requestId", "not a valid key");
        NotificationMessageHandler listener = listener(notificationService());
        when(message.getBody()).thenReturn(MessageBody.fromString(
                ProducerEnvelopes.renewedNotDeployed(details, "CERT-NEW-2")));

        listener.processAccountEvent(context);

        verify(emailProvider).sendTemplatedEmail(eq(ADMINS.get(0)), eq(NOT_DEPLOYED_SUBJECT),
                eq("cert-renewed-not-deployed"), any());
        verify(emailProvider).sendTemplatedEmail(eq(ADMINS.get(1)), eq(NOT_DEPLOYED_SUBJECT),
                eq("cert-renewed-not-deployed"), any());
        verify(recipientDelivery, never()).deliver(any(), any(), any(), any(), any(), any());
        verify(context).complete();
    }

    @Test
    void revocationFailedIsSentToEachAdminNotDropped() {
        String subject = "CertPing - Revoking the certificate for shop.example.com failed";
        NotificationMessageHandler listener = listener(notificationService());
        when(message.getBody()).thenReturn(MessageBody.fromString(ProducerEnvelopes.revocationFailed()));

        listener.processAccountEvent(context);

        for (String admin : ADMINS) {
            verify(emailProvider).sendTemplatedEmail(eq(admin), eq(subject), eq("cert-revocation-failed"), any());
        }
        verify(context).complete();
        assertThat(meterRegistry.counter(NotificationMessageHandler.UNKNOWN_ACTION_METRIC).count()).isZero();
    }

    /** The policy runs only where the listener reads a body, not again in processNotification. */
    @Test
    void processNotificationLeavesTheDeliveryFlagsAsRead() {
        NotificationEvent event = ProducerEnvelopes.read(ProducerEnvelopes.renewedNotDeployed());

        notificationService().processNotification(event);

        assertThat(event.isDeliverOnce()).isFalse();
        verify(recipientDelivery, never()).deliver(any(), any(), any(), any(), any(), any());
    }

    /** A feature event that arrives as SYSTEM_EVENT is handed over as deliver-once too. */
    @Test
    void theSystemLaneHandsAFeatureEventOverAsDeliverOnce() {
        NotificationMessageHandler listener = listener(mockedNotificationService);
        when(message.getBody()).thenReturn(MessageBody.fromString(
                ProducerEnvelopes.feature("PAUSED").replace("ACCOUNT_EVENT", "SYSTEM_EVENT")));

        listener.processSystemEvent(context);

        ArgumentCaptor<NotificationEvent> handed = ArgumentCaptor.forClass(NotificationEvent.class);
        verify(mockedNotificationService).processNotification(handed.capture());
        verify(context).complete();
        assertThat(handed.getValue().isDeliverOnce()).isTrue();
        assertThat(handed.getValue().idempotencyKey()).isEqualTo(ProducerEnvelopes.featureKey("PAUSED"));
    }

    @Test
    void aDeadLetteredRenewedNotDeployedIsRecordedUndeliveredUnderItsKey() {
        NotificationMessageHandler listener = listener(mockedNotificationService);
        when(message.getDeliveryCount()).thenReturn(3L);
        when(message.getBody()).thenReturn(MessageBody.fromString(ProducerEnvelopes.renewedNotDeployed()));

        listener.processAccountEvent(context);

        ArgumentCaptor<NotificationEvent> recorded = ArgumentCaptor.forClass(NotificationEvent.class);
        verify(undeliveredEmailService).record(recorded.capture(),
                eq(UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED), eq(message));
        assertThat(recorded.getValue().isDeliverOnce()).isTrue();
        assertThat(recorded.getValue().idempotencyKey()).isEqualTo(ProducerEnvelopes.NOT_DEPLOYED_KEY);
        verify(context).deadLetter(any(DeadLetterOptions.class));
        verify(mockedNotificationService, never()).processNotification(any(NotificationEvent.class));
    }

    @Test
    void anUnknownActionIsStillDroppedNotProcessed() {
        NotificationMessageHandler listener = listener(mockedNotificationService);
        when(message.getBody()).thenReturn(MessageBody.fromString(
                ProducerEnvelopes.feature("PAUSED").replace("FEATURE_PAUSED", "FEATURE_ARCHIVED")));

        listener.processAccountEvent(context);

        verify(context).complete();
        verify(mockedNotificationService, never()).processNotification(any(NotificationEvent.class));
        assertThat(meterRegistry.counter(NotificationMessageHandler.UNKNOWN_ACTION_METRIC).count()).isEqualTo(1.0);
    }

    /** The body through the account listener and a real NotificationService, to RecipientDelivery. */
    private NotificationEvent routedDeliverOnce(String body, String template, String subject) {
        NotificationMessageHandler listener = listener(notificationService());
        when(message.getBody()).thenReturn(MessageBody.fromString(body));

        listener.processAccountEvent(context);

        ArgumentCaptor<NotificationEvent> routed = ArgumentCaptor.forClass(NotificationEvent.class);
        verify(recipientDelivery).deliver(routed.capture(), eq(ADMINS), eq(template), eq(subject), any(), anyString());
        verify(emailProvider, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        verify(context).complete();
        assertThat(routed.getValue().isDeliverOnce()).isTrue();
        return routed.getValue();
    }

    private NotificationService notificationService() {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(emailConfig.getFrontendBaseUrl()).thenReturn("https://certping.example.com");
        when(roleEmailMapper.resolveRolesToEmails(eq(List.of("ORGANIZATION_ADMIN")), eq(42L), any(), anyBoolean()))
                .thenReturn(ADMINS);
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(invocation -> {
            NotificationRecord record = invocation.getArgument(0);
            record.setId(1L);
            return record;
        });
        when(notificationRepository.findById(1L)).thenReturn(Optional.of(new NotificationRecord()));
        return new NotificationService(notificationRepository, emailProvider,
                JsonMapper.builderWithJackson2Defaults().build(), emailConfig, roleEmailMapper, recipientDelivery, new EmailCopies(""), meterRegistry,
                event -> java.util.Optional.empty());
    }

    private NotificationMessageHandler listener(NotificationService service) {
        when(deliveryTimeouts.eventDeadline()).thenReturn(Duration.ofMinutes(5));
        when(context.getMessage()).thenReturn(message);
        when(message.getMessageId()).thenReturn("msg-abc123");
        when(message.getDeliveryCount()).thenReturn(0L);
        return new NotificationMessageHandler(service, scheduledRetryService, undeliveredEmailService,
                new SyncTaskExecutor(), meterRegistry, deliveryTimeouts);
    }

    private static <T> T mock(Class<T> type) {
        return org.mockito.Mockito.mock(type);
    }
}
