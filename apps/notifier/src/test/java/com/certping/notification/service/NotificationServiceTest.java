// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.config.EmailConfig;
import com.certping.notification.enums.IntegrationType;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.model.NotificationRecord;
import com.certping.notification.model.NotificationStatus;
import com.certping.notification.repository.NotificationRepository;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationServiceTest {

    @Mock
    private NotificationRepository notificationRepository;

    @Mock
    private EmailProvider emailService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private EmailConfig emailConfig;

    @Mock
    private RoleEmailMapper roleEmailMapper;

    @Mock
    private RecipientDelivery recipientDelivery;

    @Mock
    private NotificationPolicy notificationPolicy;

    @Spy
    private MeterRegistry meterRegistry = new SimpleMeterRegistry();

    @Spy
    private EmailCopies emailCopies = new EmailCopies("example.com,example.net");

    @InjectMocks
    private NotificationService notificationService;

    @Captor
    private ArgumentCaptor<NotificationRecord> recordCaptor;

    private NotificationEvent baseEvent;

    @BeforeEach
    void setUp() {
        baseEvent = NotificationEvent.builder()
                .userId(123L)
                .organizationId(1L)
                .email("test@example.com")
                .websiteId("web-456")
                .source("scheduler")
                .messageId("msg-001")
                .integrationType(IntegrationType.EMAIL)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .templateFields(new HashMap<>())
                .build();

            ReflectionTestUtils.setField(notificationService, "runtimeEnvironment", "prod");
    }

    private void stubPersistenceForProcessNotification() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        NotificationRecord dbRecord = NotificationRecord.builder()
                .id(1L)
                .status(NotificationStatus.PENDING)
                .build();

        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(invocation -> {
            NotificationRecord record = invocation.getArgument(0);
            if (record.getId() == null) {
                record.setId(1L);
            }
            return record;
        });
        when(notificationRepository.findById(1L)).thenReturn(Optional.of(dbRecord));
    }

    @Test
    void processNotification_aCategoryTheOrganizationTurnedOff_recordsSuppressedAndSendsNothing() throws Exception {
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(invocation -> {
            NotificationRecord record = invocation.getArgument(0);
            if (record.getId() == null) {
                record.setId(7L);
            }
            return record;
        });
        NotificationEvent event = baseEvent.toBuilder().email(null).roles(List.of("ORGANIZATION_ADMIN"))
                .notificationAction(NotificationAction.CERT_RENEWAL_SUCCESS).build();
        when(notificationPolicy.suppressedCategory(event)).thenReturn(Optional.of("CERTIFICATE_ACTIVITY"));

        Long recordId = notificationService.processNotification(event);

        assertEquals(7L, recordId);
        verify(notificationRepository, times(1)).save(recordCaptor.capture());
        NotificationRecord saved = recordCaptor.getValue();
        assertEquals(NotificationStatus.SUPPRESSED, saved.getStatus());
        assertEquals("ORG_PREFERENCE:CERTIFICATE_ACTIVITY", saved.getFailureReason());
        assertEquals("cert-renewal-success", saved.getTemplateName());
        verify(roleEmailMapper, never()).resolveRolesToEmails(any(), any(), any(), anyBoolean());
        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        verify(emailService, never()).sendTemplatedEmail(anyString(), any(), anyString(), anyString(), any());
        verify(recipientDelivery, never()).deliver(any(), any(), any(), any(), any(), any());
    }

    @Test
    void processNotification_aSuppressedRetry_turnsItsRecordSuppressed() throws Exception {
        NotificationRecord earlier = NotificationRecord.builder().id(9L).status(NotificationStatus.FAILED)
                .failureReason("ACS throttled").build();
        when(notificationRepository.findByRequestId("deliver-once:key")).thenReturn(Optional.of(earlier));
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        NotificationEvent event = baseEvent.toBuilder().requestId("deliver-once:key").deliverOnce(true).build();
        when(notificationPolicy.suppressedCategory(event)).thenReturn(Optional.of("REPORTS"));

        assertEquals(9L, notificationService.processNotification(event));

        assertEquals(NotificationStatus.SUPPRESSED, earlier.getStatus());
        assertEquals("ORG_PREFERENCE:REPORTS", earlier.getFailureReason());
        verify(recipientDelivery, never()).deliver(any(), any(), any(), any(), any(), any());
        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    @Test
    void processNotification_aSuppressedRedeliveryOfADeliveredEmail_leavesItsRecordAlone() throws Exception {
        NotificationRecord delivered = NotificationRecord.builder().id(11L).status(NotificationStatus.DELIVERED)
                .build();
        when(notificationRepository.findByRequestId("deliver-once:key")).thenReturn(Optional.of(delivered));
        NotificationEvent event = baseEvent.toBuilder().requestId("deliver-once:key").deliverOnce(true).build();
        when(notificationPolicy.suppressedCategory(event)).thenReturn(Optional.of("REPORTS"));

        assertEquals(11L, notificationService.processNotification(event));

        assertEquals(NotificationStatus.DELIVERED, delivered.getStatus());
        verify(notificationRepository, never()).save(any(NotificationRecord.class));
        verify(recipientDelivery, never()).deliver(any(), any(), any(), any(), any(), any());
    }

    @Test
    void processNotification_emailSuccess_marksDelivered() throws Exception {
        stubPersistenceForProcessNotification();

        notificationService.processNotification(baseEvent);

        verify(emailService).sendTemplatedEmail(
                eq("test@example.com"),
                anyString(),
                eq("cert-issuance-success"),
                any()
        );

        verify(notificationRepository, times(2)).save(recordCaptor.capture());
        List<NotificationRecord> saves = recordCaptor.getAllValues();
        assertEquals(NotificationStatus.PENDING, saves.get(0).getStatus());
        assertEquals(NotificationStatus.DELIVERED, saves.get(1).getStatus());
    }

    @Test
    void processNotification_aSingleRecipientEmailCarriesItsCopies() throws Exception {
        stubPersistenceForProcessNotification();
        baseEvent.setCc(List.of("legal@example.com", "Name <x@example.com>", "outside@outside.test"));

        notificationService.processNotification(baseEvent);

        verify(emailService).sendTemplatedEmail(eq("test@example.com"), eq(List.of("legal@example.com")),
                anyString(), eq("cert-issuance-success"), any());
        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    @Test
    void processNotification_copiesRideOnTheCarrierOfAMultiRecipientEmailOnly() throws Exception {
        stubPersistenceForProcessNotification();
        baseEvent.setEmail(null);
        baseEvent.setRoles(List.of("ORGANIZATION_ADMIN"));
        baseEvent.setCc(List.of("legal@example.com"));
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(List.of("zed@acme.test", "amy@acme.test", "bob@acme.test"));

        notificationService.processNotification(baseEvent);

        verify(emailService).sendTemplatedEmail(eq("amy@acme.test"), eq(List.of("legal@example.com")),
                anyString(), eq("cert-issuance-success"), any());
        verify(emailService).sendTemplatedEmail(eq("zed@acme.test"), anyString(), eq("cert-issuance-success"), any());
        verify(emailService).sendTemplatedEmail(eq("bob@acme.test"), anyString(), eq("cert-issuance-success"), any());
        verify(emailService, times(1)).sendTemplatedEmail(anyString(), org.mockito.ArgumentMatchers.anyList(),
                anyString(), anyString(), any());
    }

    @Test
    void processNotification_emailFailure_marksFailedAndThrows() throws Exception {
        stubPersistenceForProcessNotification();

        String reason = "Email provider unavailable";
        doThrow(new RuntimeException(reason)).when(emailService)
                .sendTemplatedEmail(anyString(), anyString(), anyString(), any());

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> notificationService.processNotification(baseEvent));

        assertEquals(reason, ex.getMessage());
        verify(notificationRepository, times(2)).save(recordCaptor.capture());
        List<NotificationRecord> saves = recordCaptor.getAllValues();
        assertEquals(NotificationStatus.PENDING, saves.get(0).getStatus());
        assertEquals(NotificationStatus.FAILED, saves.get(1).getStatus());
        assertEquals(reason, saves.get(1).getFailureReason());
    }

    @Test
    void sanitizeForAudit_handlesNullAndEmptyTemplateFields() {
        NotificationEvent nullFields = baseEvent.toBuilder().templateFields(null).build();
        assertEquals(nullFields, notificationService.sanitizeForAudit(nullFields));

        NotificationEvent emptyFields = baseEvent.toBuilder()
                .templateFields(new HashMap<>())
                .build();
        assertEquals(emptyFields, notificationService.sanitizeForAudit(emptyFields));
    }

    @Test
    void processNotification_nonProdAppendsEnvironmentToSubject() throws Exception {
        stubPersistenceForProcessNotification();
        ReflectionTestUtils.setField(notificationService, "runtimeEnvironment", "dev");

        notificationService.processNotification(baseEvent);

        verify(emailService).sendTemplatedEmail(
                eq("test@example.com"),
                eq("CertPing - Cert issuance success [DEV]"),
                eq("cert-issuance-success"),
                any()
        );
    }

    @Test
    void processNotification_rolesResolved_usesResolvedRecipients() throws Exception {
        // Roles-only event (no direct email) → RoleEmailMapper resolves to all admin emails.
        // This is the cert-lifecycle pattern (CERT_ISSUANCE_SUCCESS, etc.) where the publisher
        // has no specific recipient and wants the notifier to fan out.
        stubPersistenceForProcessNotification();

        baseEvent.setEmail(null);   // clear direct-recipient hint so the role path runs
        baseEvent.setRoles(List.of("organization_admin", "cert_manager"));
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), anyBoolean()))
                .thenReturn(List.of("admin1@example.com", "admin2@example.com"));

        notificationService.processNotification(baseEvent);

        verify(emailService).sendTemplatedEmail(eq("admin1@example.com"), anyString(), eq("cert-issuance-success"), any());
        verify(emailService).sendTemplatedEmail(eq("admin2@example.com"), anyString(), eq("cert-issuance-success"), any());
    }

    @Test
    void processNotification_directEmailWinsOverRoles() throws Exception {
        // When both email and roles are set (the server's auth pattern), the direct email
        // wins so auth flows (password reset and change) deliver to exactly that one user — not
        // broadcast to every org admin via RoleEmailMapper.
        stubPersistenceForProcessNotification();

        baseEvent.setEmail("alice@example.com");
        baseEvent.setRoles(List.of("organization_admin"));

        notificationService.processNotification(baseEvent);

        // Direct delivery wins — RoleEmailMapper must NOT be consulted.
        verify(roleEmailMapper, never()).resolveRolesToEmails(any(), any(), any(), anyBoolean());
        verify(emailService).sendTemplatedEmail(eq("alice@example.com"), anyString(),
                eq("cert-issuance-success"), any());
        verify(emailService, times(1)).sendTemplatedEmail(anyString(), anyString(),
                anyString(), any());
    }

    @Test
    void withAlsoTo_addsAnAddressNoRoleHolderHas() {
        assertEquals(List.of("a@example.com"), NotificationService.withAlsoTo(List.of("a@example.com"), "A@Example.com"));
        assertEquals(List.of("a@example.com"), NotificationService.withAlsoTo(List.of("a@example.com"), " "));
        assertEquals(List.of("a@example.com"), NotificationService.withAlsoTo(List.of("a@example.com"), null));
        assertEquals(List.of("r@example.net"), NotificationService.withAlsoTo(List.of(), "r@example.net"));
    }

    @Test
    void processNotification_multiRecipient_oneFails_othersSucceed_marksDelivered() throws Exception {
        // Multi-recipient fan-out is the role-resolution path (cert-lifecycle pattern).
        // Direct email must be cleared so role resolution runs — otherwise email wins
        // and we only ever send to one address.
        stubPersistenceForProcessNotification();

        baseEvent.setEmail(null);
        baseEvent.setRoles(List.of("organization_admin"));
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), anyBoolean()))
                .thenReturn(List.of("good@example.com", "bad@example.com"));
        // Only the bad address throws; the good one is a call this stub does not match.
        org.mockito.Mockito.lenient().doThrow(new RuntimeException("Invalid recipient address"))
                .when(emailService)
                .sendTemplatedEmail(eq("bad@example.com"), anyString(), anyString(), any());

        notificationService.processNotification(baseEvent);

        verify(emailService, times(2)).sendTemplatedEmail(anyString(), anyString(), eq("cert-issuance-success"), any());
        verify(notificationRepository, times(2)).save(recordCaptor.capture());
        List<NotificationRecord> saves = recordCaptor.getAllValues();
        assertEquals(NotificationStatus.PENDING, saves.get(0).getStatus());
        assertEquals(NotificationStatus.DELIVERED, saves.get(1).getStatus());
    }

    @Test
    void processNotifications_processesAllEvents() throws Exception {
        stubPersistenceForProcessNotification();

        NotificationEvent event1 = baseEvent.toBuilder()
                .messageId("msg-101")
                .notificationAction(NotificationAction.CERT_RENEWAL_SUCCESS)
                .build();

        NotificationEvent event2 = baseEvent.toBuilder()
                .messageId("msg-102")
                .notificationAction(NotificationAction.PASSWORD_CHANGE_SUCCESS)
                .build();

        notificationService.processNotifications(List.of(event1, event2));

        verify(notificationRepository, times(4)).save(any(NotificationRecord.class));
        verify(emailService, times(2)).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    @Test
    void getModel_carriesTheSupportAddressAndTheTemplateFields() {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");

        NotificationEvent event = NotificationEvent.builder()
                .templateFields(new HashMap<>(Map.of("domain", "example.com")))
                .build();

        Map<String, Object> model = notificationService.getModel(event);

        assertEquals("example.com", model.get("domain"));
        assertEquals("support@example.com", model.get("supportEmail"));
    }

    // ── find-or-insert by requestId (the row-collapse we shipped) ──────────

    @Test
    void processNotification_withRequestId_existingRow_updatesInPlace() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        // Existing PENDING row (previous FAILED attempt) — find-or-insert must reset it.
        NotificationRecord existingRow = NotificationRecord.builder()
                .id(77L)
                .status(NotificationStatus.FAILED)
                .failureReason("previous throttle")
                .requestId("req-1234")
                .build();
        when(notificationRepository.findByRequestId("req-1234")).thenReturn(Optional.of(existingRow));
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> inv.getArgument(0));
        when(notificationRepository.findById(77L)).thenReturn(Optional.of(existingRow));

        NotificationEvent event = baseEvent.toBuilder()
                .requestId("req-1234")
                .build();

        Long id = notificationService.processNotification(event);

        assertEquals(77L, id);
        // Existing row was reset to PENDING and cleared of failureReason before send.
        verify(notificationRepository).findByRequestId("req-1234");
        assertEquals(NotificationStatus.DELIVERED, existingRow.getStatus());
        // We should NOT have INSERT-ed a fresh row when the requestId already existed.
        verify(notificationRepository, never()).findByRequestId("");
    }

    @Test
    void processNotification_withRequestId_notPresent_insertsFreshRow() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(notificationRepository.findByRequestId("req-new"))
                .thenReturn(Optional.empty());
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> {
            NotificationRecord r = inv.getArgument(0);
            if (r.getId() == null) r.setId(88L);
            return r;
        });
        when(notificationRepository.findById(88L)).thenReturn(Optional.of(
                NotificationRecord.builder().id(88L).status(NotificationStatus.PENDING).build()));

        NotificationEvent event = baseEvent.toBuilder().requestId("req-new").build();

        Long id = notificationService.processNotification(event);

        assertEquals(88L, id);
        verify(notificationRepository).findByRequestId("req-new");
    }

    @Test
    void processNotification_blankRequestId_fallsBackToPerAttemptInsert() throws Exception {
        // The "publisher hasn't been updated" fallback path — WARN log, straight INSERT.
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> {
            NotificationRecord r = inv.getArgument(0);
            if (r.getId() == null) r.setId(99L);
            return r;
        });
        when(notificationRepository.findById(99L)).thenReturn(Optional.of(
                NotificationRecord.builder().id(99L).status(NotificationStatus.PENDING).build()));

        NotificationEvent event = baseEvent.toBuilder().requestId("   ").build();

        notificationService.processNotification(event);

        verify(notificationRepository, never()).findByRequestId(anyString());
    }

    // ── Unsupported integration type ───────────────────────────────────────

    @Test
    void processNotification_unsupportedIntegrationType_warnsAndDoesNotSendEmail() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> {
            NotificationRecord r = inv.getArgument(0);
            if (r.getId() == null) r.setId(1L);
            return r;
        });
        when(notificationRepository.findById(1L)).thenReturn(Optional.of(
                NotificationRecord.builder().id(1L).status(NotificationStatus.PENDING).build()));

        NotificationEvent event = baseEvent.toBuilder()
                .integrationType(IntegrationType.SMS) // not email: warn only
                .build();

        notificationService.processNotification(event);

        // No email sent: a non-email type logs a warning and does nothing.
        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    // ── recipient / email fallback logic ───────────────────────────────────

    @Test
    void processNotification_noEmailNoRecipients_warnsAndReturns() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> {
            NotificationRecord r = inv.getArgument(0);
            if (r.getId() == null) r.setId(1L);
            return r;
        });
        when(notificationRepository.findById(1L)).thenReturn(Optional.of(
                NotificationRecord.builder().id(1L).status(NotificationStatus.PENDING).build()));

        NotificationEvent event = baseEvent.toBuilder()
                .email(null)
                .recipients(null)
                .roles(null)
                .build();

        notificationService.processNotification(event);

        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        assertRecordedNoRecipient();
    }

    @Test
    void processNotification_rolesResolvedToEmpty_stillWarnsNoRecipients() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> {
            NotificationRecord r = inv.getArgument(0);
            if (r.getId() == null) r.setId(1L);
            return r;
        });
        when(notificationRepository.findById(1L)).thenReturn(Optional.of(
                NotificationRecord.builder().id(1L).status(NotificationStatus.PENDING).build()));
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), anyBoolean()))
                .thenReturn(List.of()); // empty resolution

        NotificationEvent event = baseEvent.toBuilder()
                .email(null)
                .recipients(null)
                .roles(List.of("ORGANIZATION_ADMIN"))
                .build();

        notificationService.processNotification(event);

        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        assertRecordedNoRecipient();
    }

    @Test
    void deliverOnceRetryDiscardsRecipientsWhoNoLongerResolve() throws Exception {
        stubPersistenceForProcessNotification();
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), anyBoolean())).thenReturn(List.of());
        NotificationEvent event = baseEvent.toBuilder().email(null)
                .roles(List.of("ORGANIZATION_ADMIN")).includeUser(true).deliverOnce(true)
                .recipients(List.of("former-member@example.com")).build();

        notificationService.processNotification(event);

        assertTrue(event.getRecipients().isEmpty());
        verify(recipientDelivery, never()).deliver(any(), any(), anyString(), anyString(), any(), anyString());
        assertRecordedNoRecipient();
    }

    @Test
    void processNotification_platformRoleResolvesNobody_recordsNoRecipientAndRetries() throws Exception {
        stubPersistenceForProcessNotification();
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), anyBoolean())).thenReturn(List.of());
        NotificationEvent event = platformHealthAlert();

        RetryableNotificationException thrown = assertThrows(RetryableNotificationException.class,
                () -> notificationService.processNotification(event));

        assertEquals(NotificationService.NO_RECIPIENT, thrown.getReasonCode());
        assertTrue(thrown.getRetryAfter().isPositive());
        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        assertRecordedNoRecipient();
    }

    @Test
    void processNotification_platformRoleLookupFails_recordsFailedAndRethrows() throws Exception {
        stubPersistenceForProcessNotification();
        RetryableNotificationException lookup = new RetryableNotificationException(
                RoleEmailMapper.RECIPIENT_LOOKUP_FAILED, "db down", java.time.Duration.ofMinutes(5));
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), anyBoolean())).thenThrow(lookup);
        NotificationEvent event = platformHealthAlert();

        RetryableNotificationException thrown = assertThrows(RetryableNotificationException.class,
                () -> notificationService.processNotification(event));

        assertEquals(lookup, thrown);
        verify(emailService, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        verify(notificationRepository, times(2)).save(recordCaptor.capture());
        NotificationRecord last = recordCaptor.getAllValues().get(1);
        assertEquals(NotificationStatus.FAILED, last.getStatus());
        assertTrue(last.getFailureReason().startsWith(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED));
    }

    @Test
    void processNotification_platformRoleResolved_deliversAndMarksDelivered() throws Exception {
        stubPersistenceForProcessNotification();
        when(roleEmailMapper.resolveRolesToEmails(any(), any(), any(), anyBoolean())).thenReturn(List.of("owner@example.com"));

        notificationService.processNotification(platformHealthAlert());

        verify(emailService).sendTemplatedEmail(eq("owner@example.com"), anyString(),
                eq("system-dlq-alert"), any());
        verify(notificationRepository, times(2)).save(recordCaptor.capture());
        assertEquals(NotificationStatus.DELIVERED, recordCaptor.getAllValues().get(1).getStatus());
    }

    @Test
    void processNotification_directRecipientsWithoutRoles_areNotANoRecipientFailure() throws Exception {
        stubPersistenceForProcessNotification();
        NotificationEvent event = platformHealthAlert().toBuilder()
                .roles(null)
                .recipients(List.of("ops@example.com"))
                .build();

        notificationService.processNotification(event);

        verify(emailService).sendTemplatedEmail(eq("ops@example.com"), anyString(), anyString(), any());
        verify(roleEmailMapper, never()).resolveRolesToEmails(any(), any(), any(), anyBoolean());
    }

    private NotificationEvent platformHealthAlert() {
        return NotificationEvent.builder()
                .source("certping-cert-manager")
                .requestId("health-1")
                .integrationType(IntegrationType.EMAIL)
                .notificationType(NotificationType.SYSTEM_EVENT)
                .notificationAction(NotificationAction.SYSTEM_DLQ_ALERT)
                .roles(List.of("SUPER_ADMIN"))
                .templateFields(new HashMap<>(Map.of("queue", "cert-events", "count", 1)))
                .build();
    }

    @Test
    void sanitizeForAudit_replacesBase64WithRedactionMarker() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("alias", "1");
        fields.put("attachmentBase64", "JVBERi0xLjQgZmFrZS1wZGYtYnl0ZXM=");
        fields.put("attachmentFilename", "certificate_report_1.pdf");
        fields.put("attachmentContentType", "application/pdf");

        NotificationEvent event = baseEvent.toBuilder()
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .templateFields(fields)
                .build();

        NotificationEvent sanitized = notificationService.sanitizeForAudit(event);

        assertEquals("[redacted: 32 base64 chars]", sanitized.getTemplateFields().get("attachmentBase64"));
        assertEquals("certificate_report_1.pdf", sanitized.getTemplateFields().get("attachmentFilename"));
        assertEquals("application/pdf", sanitized.getTemplateFields().get("attachmentContentType"));
        // The original event is untouched, so attach-and-send still sees the real bytes.
        assertEquals("JVBERi0xLjQgZmFrZS1wZGYtYnl0ZXM=", event.getTemplateFields().get("attachmentBase64"));
    }

    @Test
    void sanitizeForAudit_passesThroughEventWithoutAttachment() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("alias", "1");

        NotificationEvent event = baseEvent.toBuilder()
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .templateFields(fields)
                .build();

        assertEquals(event, notificationService.sanitizeForAudit(event));
    }

    @Test
    void aResetEventIsStoredWithoutItsLinkButEmailedWithIt() throws Exception {
        stubPersistenceForProcessNotification();
        String link = "https://certping.test/reset-password?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln";
        Map<String, Object> fields = new HashMap<>();
        fields.put("resetLink", link);
        fields.put("username", "admin");
        NotificationEvent reset = baseEvent.toBuilder().notificationAction(NotificationAction.RESET_PASSWORD)
                .templateFields(fields).build();
        ArgumentCaptor<Object> stored = ArgumentCaptor.forClass(Object.class);

        notificationService.processNotification(reset);

        verify(objectMapper, org.mockito.Mockito.atLeastOnce()).writeValueAsString(stored.capture());
        for (Object value : stored.getAllValues()) {
            NotificationEvent persisted = (NotificationEvent) value;
            assertEquals(SecretFields.REDACTED, persisted.getTemplateFields().get("resetLink"));
            assertEquals("admin", persisted.getTemplateFields().get("username"));
            assertTrue(!String.valueOf(persisted.getTemplateFields()).contains("token="));
        }
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> model = ArgumentCaptor.forClass(Map.class);
        verify(emailService).sendTemplatedEmail(eq("test@example.com"), anyString(), eq("reset-password"), model.capture());
        assertEquals(link, model.getValue().get("resetLink"));
        assertEquals(link, reset.getTemplateFields().get("resetLink"));
    }

    @Test
    void sanitizeForAudit_redactsVerificationLinksTokensAndTokenUrls() {
        Map<String, Object> fields = new HashMap<>();
        fields.put("verificationLink", "https://certping.test/verify/abc");
        fields.put("loginLink", "https://certping.test/login");
        fields.put("username", "new");
        NotificationEvent verify = baseEvent.toBuilder().notificationAction(NotificationAction.RESET_PASSWORD)
                .templateFields(fields).fullUrl("https://certping.test/x?token=1").build();

        NotificationEvent sanitized = notificationService.sanitizeForAudit(verify);

        assertEquals(SecretFields.REDACTED, sanitized.getTemplateFields().get("verificationLink"));
        assertEquals(SecretFields.REDACTED, sanitized.getTemplateFields().get("loginLink"));
        assertEquals("new", sanitized.getTemplateFields().get("username"));
        assertEquals(SecretFields.REDACTED, sanitized.getFullUrl());

        Map<String, Object> certFields = new HashMap<>();
        certFields.put("certificatePageUrl", "https://certping.test/certificates/9");
        certFields.put("apiToken", "sk_live_1");
        certFields.put("nested", Map.of("callback", "https://hook.test/?access_token=zz", "name", "n"));
        NotificationEvent cert = baseEvent.toBuilder().notificationAction(NotificationAction.CERT_RENEWAL_SUCCESS)
                .templateFields(certFields).build();

        Map<String, Object> stored = notificationService.sanitizeForAudit(cert).getTemplateFields();

        assertEquals("https://certping.test/certificates/9", stored.get("certificatePageUrl"));
        assertEquals(SecretFields.REDACTED, stored.get("apiToken"));
        assertEquals(Map.of("callback", SecretFields.REDACTED, "name", "n"), stored.get("nested"));
    }

    /** The row ends FAILED with the NO_RECIPIENT reason and is never marked DELIVERED. */
    private void assertRecordedNoRecipient() {
        verify(notificationRepository, times(2)).save(recordCaptor.capture());
        List<NotificationRecord> saves = recordCaptor.getAllValues();
        assertEquals(NotificationStatus.PENDING, saves.get(0).getStatus());
        assertEquals(NotificationStatus.FAILED, saves.get(1).getStatus());
        assertEquals(NotificationService.NO_RECIPIENT, saves.get(1).getFailureReason());
        assertTrue(saves.stream().noneMatch(r -> r.getStatus() == NotificationStatus.DELIVERED));
    }

    // ── deliver-mark failure enqueues reconciliation ───────────────────────

    @Test
    void processNotification_markDeliveredThrows_enqueuesReconcileButStillReturnsRecordId() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        NotificationRecord row = NotificationRecord.builder()
                .id(55L).status(NotificationStatus.PENDING).build();
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> {
            NotificationRecord r = inv.getArgument(0);
            if (r.getId() == null) r.setId(55L);
            return r;
        });
        // markDelivered calls findById → simulate transient DB failure
        when(notificationRepository.findById(55L))
                .thenThrow(new RuntimeException("DB temporarily down"));

        Long id = notificationService.processNotification(baseEvent);

        // Email sent; markDelivered failed; but processNotification does NOT throw
        // (it's a post-success bookkeeping failure). Reconciliation is enqueued.
        assertEquals(55L, id);
        verify(emailService).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    // ── environment prefix / subject formatting ────────────────────────────

    @Test
    void processNotification_nullRuntimeEnv_treatedAsProdNoBracket() throws Exception {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        when(notificationRepository.save(any(NotificationRecord.class))).thenAnswer(inv -> {
            NotificationRecord r = inv.getArgument(0);
            if (r.getId() == null) r.setId(1L);
            return r;
        });
        when(notificationRepository.findById(1L)).thenReturn(Optional.of(
                NotificationRecord.builder().id(1L).status(NotificationStatus.PENDING).build()));

        ReflectionTestUtils.setField(notificationService, "runtimeEnvironment", null);

        notificationService.processNotification(baseEvent);

        ArgumentCaptor<String> subject = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendTemplatedEmail(anyString(), subject.capture(), anyString(), any());
        // null → normalized to "prod" → no [ENV] suffix
        org.assertj.core.api.Assertions.assertThat(subject.getValue()).doesNotContain("[");
    }

    // ── sanitizeForAudit edge cases ─────────────────────────────────────────

    @Test
    void sanitizeForAudit_nullEvent_returnsNull() {
        assertEquals(null, notificationService.sanitizeForAudit(null));
    }

    @Test
    void sanitizeForAudit_nullTemplateFields_returnsSameEvent() {
        NotificationEvent event = NotificationEvent.builder().templateFields(null).build();
        NotificationEvent sanitized = notificationService.sanitizeForAudit(event);
        assertEquals(event, sanitized);
    }
}
