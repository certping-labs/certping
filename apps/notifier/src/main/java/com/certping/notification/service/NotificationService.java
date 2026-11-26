// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.IntegrationType;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.model.NotificationRecord;
import com.certping.notification.model.NotificationStatus;
import com.certping.notification.repository.NotificationRepository;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import com.certping.notification.config.EmailConfig;
import org.springframework.beans.factory.annotation.Value;
import tools.jackson.core.JacksonException;

import java.time.OffsetDateTime;
import java.util.Locale;
import com.certping.notification.utils.RequestContextLogger;
import com.certping.notification.utils.SafeFailure;
import com.certping.notification.interceptor.RequestContextInterceptor;
import com.certping.notification.util.OtelSpanContext;
import org.slf4j.Logger;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    private final NotificationRepository notificationRepository;
    private final EmailProvider emailService;
    private final ObjectMapper objectMapper;
    private final EmailConfig emailConfig;
    private final RoleEmailMapper roleEmailMapper;
    private final RecipientDelivery recipientDelivery;
    private final EmailCopies emailCopies;
    private final MeterRegistry meterRegistry;
    private final NotificationPolicy notificationPolicy;

    @Value("${ENVIRONMENT:${spring.profiles.active:prod}}")
    private String runtimeEnvironment = "prod";

    private static final int MAX_EMAIL_SUBJECT_LENGTH = 150;
    /** The length of notification_records.failure_reason. */
    private static final int MAX_FAILURE_REASON_LENGTH = 1000;

    static final String NO_RECIPIENT = "NO_RECIPIENT";
    /** failure_reason of a SUPPRESSED record, followed by the category the organization turned off. */
    static final String SUPPRESSED_REASON = "ORG_PREFERENCE:";
    /** Counts emails nobody could receive, by action and publisher, for paging. */
    static final String NO_RECIPIENT_METRIC = "notification.no_recipient";
    /**
     * A person has to add a super admin or set the bootstrap address, so retries are spaced out and
     * the scheduled-retry budget covers hours rather than minutes.
     */
    private static final Duration NO_RECIPIENT_RETRY_AFTER = Duration.ofMinutes(30);

    public void processNotifications(List<NotificationEvent> events) {
        events.forEach(this::processNotification);
    }

    /**
     * Processes a single notification event to end-to-end delivery.
     *
     * <p>Row semantics: <b>one row per logical notification, keyed by
     * {@link NotificationEvent#idempotencyKey()}.</b> On every attempt (first
     * delivery and any subsequent scheduled retry), we
     * {@code findByRequestId → update} — resetting status to PENDING and
     * clearing the previous failure reason. If no row exists (first attempt),
     * we INSERT. This means the same row's state reflects the LATEST attempt;
     * ops sees one row per user notification, not one row per retry attempt.
     *
     * <p>The retry preservation is automatic: {@link ScheduledRetryService}
     * copies the message body verbatim onto the future-dated retry, so the
     * embedded {@code requestId} on each event is preserved without any
     * broker-level or DB-id plumbing.
     *
     * @return the row id used for this attempt (useful for logging /
     *         downstream tooling). Null for deliver-once events (one row per recipient).
     *
     * <p>No transaction spans the method: each repository call commits on its own. A users query
     * that fails aborts the transaction it runs in, and inside a shared one the attempt's row could
     * then not be written, so the failure would be neither recorded nor retried.
     */
    public Long processNotification(NotificationEvent event) {
        enrichSpanFromEvent(event);
        Optional<String> turnedOff = notificationPolicy.suppressedCategory(event);
        if (turnedOff.isPresent()) {
            return recordSuppressed(event, turnedOff.get());
        }
        // Recipient resolution — direct-email wins over role resolution.
        //
        // A publisher that populates {@code email} is asking for delivery to exactly that user. The
        // {@code roles} path is reserved for cert-lifecycle events where the publisher has no specific
        // recipient and wants the notifier to fan out to all org admins (CERT_ISSUANCE_SUCCESS, etc.).
        //
        // Order of preference:
        //   1. event.email present  → deliver to that one address (auth pattern: password reset and change)
        //   2. event.roles present  → resolve via RoleEmailMapper to all matching admin emails
        //   3. neither, or nobody resolved → FAILED with NO_RECIPIENT (see recordNoRecipient)
        //
        // Keeping both fields on the wire is intentional — publishers can populate {@code roles} as
        // a fallback hint, but {@code email} always takes precedence when set. This avoids the
        // broadcast hazard where every org admin would get a user's personal password-reset link.
        RetryableNotificationException recipientLookupFailure = null;
        if (event.getEmail() != null && !event.getEmail().isBlank()) {
            event.setRecipients(List.of(event.getEmail()));
            contextLogger().debug("Direct-recipient delivery to the one address the event names");
        } else if ((event.getRoles() != null && !event.getRoles().isEmpty()) || event.isIncludeUser()) {
            try {
                List<String> resolvedEmails = withAlsoTo(roleEmailMapper.resolveRolesToEmails(
                        event.getRoles(), event.getOrganizationId(), event.getUserId(), event.isIncludeUser()),
                        event.getAlsoTo());
                event.setRecipients(resolvedEmails);
                if (!resolvedEmails.isEmpty()) {
                    contextLogger().info("Resolved roles {} to {} recipient emails",
                            event.getRoles(), resolvedEmails.size());
                }
            } catch (RetryableNotificationException e) {
                // Thrown once the attempt has its row, so the failure is recorded there.
                recipientLookupFailure = e;
            }
        }

        String templateName = resolveTemplateName(event);

        Map<String, Object> model = getModel(event);
        explicitCheck(templateName, model, event.getIntegrationType());

        String subject = applyEnvironmentToSubject(generateEmailSubject(event));

        if (event.isDeliverOnce() && isEmail(event.getIntegrationType())) {
            return deliverToEachRecipient(event, recipientLookupFailure, templateName, subject, model);
        }

        NotificationRecord draft = buildDraftRecord(event, subject);
        contextLogger().debug("Notification event Received for integration type: {}", event.getIntegrationType());

        NotificationRecord record = requestRecord(event, draft);

        if (recipientLookupFailure != null) {
            markFailed(record.getId(), failureReason(recipientLookupFailure));
            throw recipientLookupFailure;
        }
        event.setRecipients(deliverable(event.getRecipients()));
        if (isEmail(event.getIntegrationType()) && event.getRecipients().isEmpty()) {
            return recordNoRecipient(event, record.getId());
        }

        //SEND to all recipients. Total failure (no successful send) → mark FAILED and THROW → the queue redelivers.
        //Partial success: invalid addresses do not fail the message or re-blast good recipients on retry.
        try {
            sendNotificationByType(event.getIntegrationType(), event, templateName, subject, model);
        } catch (Exception e) {
            markFailed(record.getId(), e.getMessage());
            throw e;
        }

        //Email sent OK. Try to mark DELIVERED. DO NOT THROW if this fails.
        try {
            markDelivered(record.getId());
        } catch (Exception e) {
            enqueueDeliveryReconcile(record.getId());
            contextLogger().error("Email sent but failed to update DB for recordId {}: {}", record.getId(), e.getMessage(), e);
        }
        return record.getId();
    }

    /**
     * A deliver-once email: one record per recipient, each sent at most once per claim, retried until
     * every recipient has it (RecipientDelivery). A request-level record exists only when nobody can
     * receive it.
     */
    private Long deliverToEachRecipient(NotificationEvent event, RetryableNotificationException recipientLookupFailure,
                                        String templateName, String subject, Map<String, Object> model) {
        if (recipientLookupFailure != null) {
            throw recipientLookupFailure;
        }
        List<String> recipients = deliverable(event.getRecipients());
        if (recipients.isEmpty()) {
            return recordNoRecipient(event, requestRecord(event, buildDraftRecord(event, subject)).getId());
        }
        recipientDelivery.deliver(event, recipients, templateName, subject, model, auditPayload(event));
        return null;
    }

    /**
     * One row per logical notification, keyed by requestId: a retry resets the row to PENDING and
     * refreshes what it may have changed. A legacy publisher without a requestId gets a row per attempt.
     */
    private NotificationRecord requestRecord(NotificationEvent event, NotificationRecord draft) {
        String requestId = event.idempotencyKey();
        if (requestId == null || requestId.isBlank()) {
            contextLogger().warn(
                    "Event has no requestId — falling back to per-attempt INSERT (publisher should populate requestId)");
            draft.setStatus(NotificationStatus.PENDING);
            return notificationRepository.save(draft);
        }
        return notificationRepository.findByRequestId(requestId)
                .map(existing -> {
                    existing.setStatus(NotificationStatus.PENDING);
                    existing.setFailureReason(null);
                    existing.setSubject(draft.getSubject());
                    existing.setPayloadJson(draft.getPayloadJson());
                    existing.setCorrelationId(draft.getCorrelationId());
                    return notificationRepository.save(existing);
                })
                .orElseGet(() -> {
                    draft.setStatus(NotificationStatus.PENDING);
                    return notificationRepository.save(draft);
                });
    }

    /**
     * An email nobody can receive is FAILED, never DELIVERED. A platform alert is retried: its
     * publisher holds a cooldown and will not send it again, and adding a super admin or setting
     * the bootstrap address fixes it. Any other event has no one to wait for, so it is not retried.
     */
    private Long recordNoRecipient(NotificationEvent event, Long recordId) {
        markFailed(recordId, NO_RECIPIENT);
        meterRegistry.counter(NO_RECIPIENT_METRIC, "action", event.getNotificationAction().name(),
                "source", String.valueOf(event.getSource())).increment();
        if (RoleEmailMapper.addressesPlatformRole(event.getRoles(), event.getOrganizationId(), event.getUserId())) {
            throw new RetryableNotificationException(NO_RECIPIENT,
                    "No recipient for platform roles " + event.getRoles(), NO_RECIPIENT_RETRY_AFTER);
        }
        contextLogger().warn("No recipients available for email notification; recorded {} as {}", recordId, NO_RECIPIENT);
        return recordId;
    }

    /**
     * The organization turned this notification's category off: one SUPPRESSED record under the
     * event's key, and nothing is resolved, sent or retried.
     */
    private Long recordSuppressed(NotificationEvent event, String category) {
        String requestId = event.idempotencyKey();
        NotificationRecord existing = requestId == null || requestId.isBlank()
                ? null
                : notificationRepository.findByRequestId(requestId).orElse(null);
        if (existing != null && (existing.getStatus() == NotificationStatus.DELIVERED
                || existing.getStatus() == NotificationStatus.SENT)) {
            return existing.getId();
        }
        NotificationRecord record = existing != null
                ? existing
                : buildDraftRecord(event, applyEnvironmentToSubject(generateEmailSubject(event)));
        record.setStatus(NotificationStatus.SUPPRESSED);
        record.setFailureReason(SUPPRESSED_REASON + category);
        record = notificationRepository.save(record);
        contextLogger().info("Notification not sent, category {} turned off by organization {}: record {}",
                category, event.getOrganizationId(), record.getId());
        return record.getId();
    }

    private static boolean isEmail(IntegrationType type) {
        return type == null || type == IntegrationType.EMAIL;
    }

    /** The role holders and alsoTo, once: an address a role holder has, ignoring letter case, is not added again. */
    static List<String> withAlsoTo(List<String> holders, String alsoTo) {
        if (alsoTo == null || alsoTo.isBlank()) {
            return holders;
        }
        String extra = alsoTo.trim();
        if (holders.stream().anyMatch(holder -> holder != null && holder.trim().equalsIgnoreCase(extra))) {
            return holders;
        }
        List<String> all = new ArrayList<>(holders);
        all.add(extra);
        return all;
    }

    private static List<String> deliverable(List<String> recipients) {
        if (recipients == null) {
            return List.of();
        }
        return recipients.stream()
                .filter(recipient -> recipient != null && !recipient.isBlank())
                .map(String::trim)
                .toList();
    }

    private static String failureReason(RetryableNotificationException e) {
        String reason = e.getReasonCode() + ": " + e.getMessage();
        return reason.length() <= MAX_FAILURE_REASON_LENGTH ? reason : reason.substring(0, MAX_FAILURE_REASON_LENGTH);
    }

    private void sendNotificationByType(IntegrationType type, NotificationEvent event, String templateName, String subject, Map<String, Object> model) {
        if (isEmail(type)) {
            List<String> recipients = event.getRecipients();
            List<String> copies = emailCopies.of(event, recipients);
            int carrier = EmailCopies.carrier(recipients);
            if (recipients.size() == 1) {
                EmailCopies.send(emailService, recipients.get(0), copies, subject, templateName, model);
                return;
            }
            int successCount = 0;
            Exception firstFailure = null;
            for (int i = 0; i < recipients.size(); i++) {
                String recipient = recipients.get(i);
                try {
                    EmailCopies.send(emailService, recipient, i == carrier ? copies : List.of(), subject, templateName, model);
                    successCount++;
                } catch (Exception e) {
                    if (firstFailure == null) {
                        firstFailure = e;
                    }
                    contextLogger().error("Failed to send to recipient: {}", SafeFailure.describe(e));
                }
            }
            if (successCount == 0) {
                if (firstFailure instanceof RuntimeException re) {
                    throw re;
                }
                throw new RuntimeException("All recipient sends failed", firstFailure);
            }
        } else {
            // The server publishes EMAIL only and delivers Slack and Teams webhooks itself.
            contextLogger().warn("Unsupported integration type: {}", type);
        }
    }

    private void explicitCheck(String templateName, Map<String, Object> model, IntegrationType type) {
        // no special-case template handling required
    }

    private String resolveTemplateName(NotificationEvent event) {
        return event.getNotificationAction().name().toLowerCase().replace("_", "-");
    }

    private String generateEmailSubject(NotificationEvent event) {
        if (event.getNotificationAction() == NotificationAction.IOT_ACTIVITY_DIGEST) {
            // prettifyEnum would render "Iot Activity Digest".
            return "CertPing - IoT certificate activity";
        }
        if (event.getNotificationAction() == NotificationAction.IOT_CRITICAL_ALERT
                || event.getNotificationAction() == NotificationAction.IOT_WARNING_ALERT) {
            return iotAlertSubject(event);
        }
        if (FeatureLifecycleEmail.handles(event.getNotificationAction())) {
            return FeatureLifecycleEmail.subject(event);
        }
        if (RenewedNotDeployedEmail.handles(event.getNotificationAction())) {
            return RenewedNotDeployedEmail.subject(event);
        }
        if (CertPingDnsKeyExpiringEmail.handles(event.getNotificationAction())) {
            return CertPingDnsKeyExpiringEmail.subject(event);
        }
        if (RevocationFailedEmail.handles(event.getNotificationAction())) {
            return RevocationFailedEmail.subject(event);
        }
        return String.format("CertPing - %s", prettifyEnum(event.getNotificationAction()));
    }

    /** The alert title is the subject: one action carries many scenarios, so the enum name says nothing. */
    private String iotAlertSubject(NotificationEvent event) {
        Object title = event.getTemplateFields() == null
                ? null
                : event.getTemplateFields().get("alertTitle");
        if (title == null || String.valueOf(title).isBlank()) {
            return "CertPing - Device certificate alert";
        }
        String subject = "CertPing - " + String.valueOf(title).trim().replaceAll("[\\r\\n]+", " ");
        return subject.substring(0, Math.min(subject.length(), MAX_EMAIL_SUBJECT_LENGTH));
    }

    private String applyEnvironmentToSubject(String baseSubject) {
        if (!isNonProdEnvironment()) {
            return baseSubject;
        }
        return String.format("%s [%s]", baseSubject, environmentLabel());
    }

    private boolean isNonProdEnvironment() {
        String env = normalizeEnvironment();
        return !env.isBlank() && !"prod".equals(env) && !"production".equals(env);
    }

    private String normalizeEnvironment() {
        return runtimeEnvironment == null ? "prod" : runtimeEnvironment.trim().toLowerCase(Locale.ROOT);
    }

    private String environmentLabel() {
        String env = normalizeEnvironment();
        return env.isBlank() ? "UNKNOWN" : env.toUpperCase(Locale.ROOT);
    }

    // Recursive flatten utility for nested maps
    private void flattenMap(Map<String, Object> source, String prefix, Map<String, Object> target) {
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                flattenMap(nestedMap, key, target);
            } else {
                target.put(key, value);
            }
        }
    }

    Map<String, Object> getModel(NotificationEvent event) {
        Map<String, Object> model = new HashMap<>();
        if (event.getTemplateFields() != null) {
            flattenMap(event.getTemplateFields(), "templateFields", model);
            flattenMap(event.getTemplateFields(), "", model);
            // Also keep the full map for legacy {{templateFields.key}}
            model.put("templateFields", event.getTemplateFields());
        }
        model.put("userId", event.getUserId());
        model.put("organizationId", event.getOrganizationId());
        model.put("email", event.getEmail());
        model.put("websiteId", event.getWebsiteId());
        model.put("fullUrl", event.getFullUrl());
        model.put("status", event.getStatus());
        model.put("source", event.getSource());
        model.put("notificationType", event.getNotificationType());
        model.put("notificationAction", event.getNotificationAction());
        model.put("integrationType", event.getIntegrationType());
        model.put("supportEmail", emailConfig.getSupportAddress());
        model.put("frontendBaseUrl", emailConfig.getFrontendBaseUrl());
        if (FeatureLifecycleEmail.handles(event.getNotificationAction())) {
            FeatureLifecycleEmail.prepareModel(event, model);
        }
        if (RenewedNotDeployedEmail.handles(event.getNotificationAction())) {
            RenewedNotDeployedEmail.prepareModel(event, model);
        }
        if (CertPingDnsKeyExpiringEmail.handles(event.getNotificationAction())) {
            CertPingDnsKeyExpiringEmail.prepareModel(event, model);
        }
        if (RevocationFailedEmail.handles(event.getNotificationAction())) {
            RevocationFailedEmail.prepareModel(event, model);
        }
        return model;
    }

    private String prettifyEnum(Enum<?> value) {
        return value == null ? "N/A" : value.name().substring(0, 1).toUpperCase() + value.name().substring(1).toLowerCase().replace('_', ' ');
    }

    /** What the audit row records of the event: never the attachment bytes (sanitizeForAudit). */
    private String auditPayload(NotificationEvent event) {
        try {
            return objectMapper.writeValueAsString(sanitizeForAudit(event));
        } catch (JacksonException e) {
            throw new RuntimeException("Failed to serialize notification event", e);
        }
    }

    private NotificationRecord buildDraftRecord(NotificationEvent event, String subject) throws RuntimeException {
        String payloadJson = auditPayload(event);
        NotificationRecord record = NotificationRecord.builder()
                .userId(event.getUserId()) // Can be null for organization or platform events
                .organizationId(event.getOrganizationId())
                .email(event.getEmail())
                .templateName(event.getNotificationAction().name().toLowerCase().replace("_", "-"))
                .integrationType(IntegrationType.EMAIL)
                .subject(subject)
                .sentBy(event.getSource())
                .payloadJson(payloadJson)
                .requestId(event.idempotencyKey())
                .correlationId(event.getCorrelationId())
                .status(NotificationStatus.PENDING)
                .build();
        return record;
    }

    /**
     * Returns a copy of {@code event} suitable for persistence in the
     * {@code notification_records.payload_json} audit column.
     *
     * <p>Large attachment bytes are replaced with a size marker, so
     * the audit row does not carry tens of KB per notification. Delivery still uses the
     * original event, so the complete content remains available to the email provider.
     *
     * <p>Reset and verification links, tokens and other secrets are replaced too (SecretFields):
     * the stored row must never let a reader take an account.
     */
    NotificationEvent sanitizeForAudit(NotificationEvent event) {
        if (event == null) {
            return event;
        }
        String fullUrl = event.getFullUrl();
        boolean urlSecret = SecretFields.holdsSecret(fullUrl);
        if (event.getTemplateFields() == null) {
            return urlSecret ? event.toBuilder().fullUrl(SecretFields.REDACTED).build() : event;
        }
        Map<String, Object> redacted = null;
        Object base64 = event.getTemplateFields().get("attachmentBase64");
        if (base64 != null) {
            redacted = new HashMap<>(event.getTemplateFields());
            int bytes = String.valueOf(base64).length();
            redacted.put("attachmentBase64", "[redacted: " + bytes + " base64 chars]");
        }
        Map<String, Object> source = redacted == null ? event.getTemplateFields() : redacted;
        Map<String, Object> withoutSecrets = SecretFields.redact(event.getNotificationAction(), source);
        if (withoutSecrets != source) {
            redacted = withoutSecrets;
        }

        if (redacted == null && !urlSecret) {
            return event;
        }
        NotificationEvent.NotificationEventBuilder copy = event.toBuilder();
        if (redacted != null) {
            copy.templateFields(redacted);
        }
        if (urlSecret) {
            copy.fullUrl(SecretFields.REDACTED);
        }
        return copy.build();
    }

    /** Mark DELIVERED. */
    private void markDelivered(Long id) {
        NotificationRecord record = notificationRepository.findById(id).orElse(null);
        if (record != null) {
            record.setStatus(NotificationStatus.DELIVERED);
            record.setSentAt(OffsetDateTime.now(ZoneOffset.UTC));
            notificationRepository.save(record);
        } else {
            contextLogger().warn("markDelivered: record {} not found", id);
        }
    }

    /** Mark FAILED (used when send fails). */
    private void markFailed(Long id, String reason) {
        NotificationRecord record = notificationRepository.findById(id).orElse(null);
        if (record != null) {
            record.setStatus(NotificationStatus.FAILED);
            record.setFailureReason(reason);
            notificationRepository.save(record);
        } else {
            contextLogger().warn("markFailed: record {} not found", id);
        }
    }

    /** Optional: enqueue a repair task to flip PENDING→DELIVERED when email succeeded but update failed. */
    private void enqueueDeliveryReconcile(Long recordId) {
        // Implement with your jobs system (Quartz, Spring @Scheduled, or a lightweight queue)
        contextLogger().warn("Enqueued delivery reconcile for record {}", recordId);
    }

    private void enrichSpanFromEvent(NotificationEvent event) {
        String requestId = RequestContextInterceptor.getCurrentRequestId();
        if ("unknown".equals(requestId) && event.getMessageId() != null) {
            requestId = event.getMessageId();
        }
        OtelSpanContext.enrichNotificationConsume(
                requestId,
                RequestContextInterceptor.getCurrentCorrelationId(),
                event.getOrganizationId() != null ? event.getOrganizationId().toString() : null,
                OtelSpanContext.fieldAsString(event.getTemplateFields(), "certificateXref"),
                event.getNotificationAction() != null ? event.getNotificationAction().name() : null,
                event.getNotificationType() != null ? event.getNotificationType().name() : null,
                event.getMessageId(),
                event.getUserId() != null ? event.getUserId().toString() : null);
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(NotificationService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
