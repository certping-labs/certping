// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.TransportMessage;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.MessageSender;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.interceptor.RequestContextInterceptor;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.utils.MessageIds;
import com.certping.notification.utils.SafeFailure;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

import static org.springframework.web.util.HtmlUtils.htmlEscape;

/**
 * Deliver-once emails that have not reached every recipient: each is recorded once per request,
 * the super admins are alerted once, and one whose retries ran out is replayed hourly, a few times,
 * on its original retry chain. {@value #UNDELIVERED_GAUGE} counts those a replay can still deliver;
 * an email refused for good is alerted but not counted, since nothing will change it.
 */
@Service
@Slf4j
public class UndeliveredEmailService {

    static final String UNDELIVERED_GAUGE = "notification.deliver_once.undelivered.open";
    static final String PERMANENT_FAILURE = "PERMANENT_FAILURE";

    private static final String RETRIES_EXHAUSTED_REASON = "RETRIES_EXHAUSTED";
    private static final String ALERT_CLAIMED = "UNDELIVERED_ALERT_CLAIMED";
    private static final String ALERT_SENT = "UNDELIVERED_ALERT_SENT";
    private static final String RECORD_MARKER = "undelivered-email";
    private static final String ALERT_SUBJECT = "CertPing - Email delivery needs attention";
    private static final int REPLAY_BATCH_SIZE = 50;
    private static final int GAUGE_BATCH_SIZE = 1000;

    public enum Outcome {
        RETRIES_EXHAUSTED("FAILED", RETRIES_EXHAUSTED_REASON),
        PENDING_RETRY("PENDING", RETRIES_EXHAUSTED_REASON),
        PERMANENT_FAILURE("FAILED", UndeliveredEmailService.PERMANENT_FAILURE);

        private final String status;
        private final String reason;

        Outcome(String status, String reason) {
            this.status = status;
            this.reason = reason;
        }
    }

    /**
     * Records the request once. A later record updates it only while it is neither delivered nor
     * final, and never with a payload of fewer replays than the one stored.
     */
    private static final String RECORD_SQL = """
            INSERT INTO notification_records (request_id, user_id, organization_id, integration_type, template_name,
                status, payload_json, failure_reason, correlation_id, created_at, updated_at)
            VALUES (?, ?, ?, 'EMAIL', ?, ?, ?, ?, ?, clock_timestamp(), clock_timestamp())
            ON CONFLICT (request_id) WHERE request_id IS NOT NULL DO UPDATE
            SET status = EXCLUDED.status,
                template_name = EXCLUDED.template_name,
                payload_json = EXCLUDED.payload_json,
                failure_reason = EXCLUDED.failure_reason,
                updated_at = clock_timestamp()
            WHERE notification_records.status <> 'DELIVERED'
              AND notification_records.failure_reason IS DISTINCT FROM 'NO_RECIPIENT'
              AND notification_records.failure_reason IS DISTINCT FROM 'PERMANENT_FAILURE'
              AND (notification_records.template_name IS DISTINCT FROM ?
                   OR COALESCE((notification_records.payload_json::jsonb #>> '{0,replayCount}')::int, 0)
                      <= COALESCE((EXCLUDED.payload_json::jsonb #>> '{0,replayCount}')::int, 0))
            """;

    /** Takes the exhausted requests due a replay and counts the replay in their payload. */
    private static final String REPLAY_SQL = """
            WITH due AS (
                SELECT candidate.id,
                       COALESCE((candidate.payload_json::jsonb #>> '{0,replayCount}')::int, 0) AS replay_count
                FROM notification_records AS candidate
                WHERE candidate.status = 'FAILED' AND candidate.template_name = ?
                  AND candidate.failure_reason = ?
                  AND candidate.created_at >= clock_timestamp() - interval '30 days'
                  AND candidate.updated_at < clock_timestamp() - interval '1 hour'
                  AND COALESCE((candidate.payload_json::jsonb #>> '{0,replayCount}')::int, 0) < ?
                ORDER BY candidate.created_at
                LIMIT ?
                FOR UPDATE OF candidate SKIP LOCKED
            )
            UPDATE notification_records AS record
            SET status = 'PENDING', updated_at = clock_timestamp(),
                payload_json = jsonb_set(record.payload_json::jsonb, '{0,replayCount}',
                    to_jsonb(due.replay_count + 1))::text
            FROM due
            WHERE record.id = due.id
            RETURNING record.id, record.request_id, record.payload_json
            """;

    /** Puts back a request whose replay could not be published, and its replay count with it. */
    private static final String REPLAY_FAILED_SQL = """
            UPDATE notification_records
            SET status = 'FAILED',
                payload_json = jsonb_set(payload_json::jsonb, '{0,replayCount}',
                    to_jsonb(GREATEST(COALESCE((payload_json::jsonb #>> '{0,replayCount}')::int, 0) - 1, 0)))::text
            WHERE id = ? AND status = 'PENDING'
            """;

    private static final String RESOLVE_SQL = """
            UPDATE notification_records
            SET status = 'DELIVERED', failure_reason = NULL, sent_at = clock_timestamp(), updated_at = clock_timestamp()
            WHERE request_id = ? AND template_name = ? AND status <> 'DELIVERED'
              AND NOT EXISTS (SELECT 1 FROM notification_records AS recipient
                              WHERE starts_with(recipient.request_id, ?) AND recipient.status <> 'DELIVERED')
            """;

    private static final String OPEN_COUNT_SQL = """
            SELECT count(*) FROM (
                SELECT id FROM notification_records
                WHERE status IN ('FAILED', 'PENDING') AND template_name = ?
                  AND failure_reason IS DISTINCT FROM 'NO_RECIPIENT'
                  AND failure_reason IS DISTINCT FROM 'PERMANENT_FAILURE'
                  AND created_at >= clock_timestamp() - interval '30 days'
                LIMIT ?
            ) AS open_requests
            """;

    /** One alert per request, taken again only if its sender died an hour ago without finishing. */
    private static final String CLAIM_ALERT_SQL = """
            UPDATE notification_records SET sent_by = ?, sent_at = clock_timestamp()
            WHERE request_id = ? AND template_name = ? AND status <> 'DELIVERED'
              AND (sent_by IS NULL OR (sent_by = ? AND sent_at < clock_timestamp() - interval '1 hour'))
            """;

    private static final String SET_ALERT_SQL = "UPDATE notification_records SET sent_by = ? WHERE request_id = ? AND sent_by = ?";

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final RoleEmailMapper roleEmailMapper;
    private final EmailProvider emailProvider;
    private final MessageSender sender;
    private final int maxReplays;

    public UndeliveredEmailService(JdbcTemplate jdbc, ObjectMapper mapper, RoleEmailMapper roleEmailMapper,
                                   EmailProvider emailProvider, MessageSender sender, MeterRegistry registry,
                                   @Value("${notifier.delivery.max-replays:3}") int maxReplays) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.roleEmailMapper = roleEmailMapper;
        this.emailProvider = emailProvider;
        this.sender = sender;
        this.maxReplays = maxReplays;
        Gauge.builder(UNDELIVERED_GAUGE, this, UndeliveredEmailService::openCount)
                .description("Deliver-once requests a replay can still deliver").register(registry);
    }

    public boolean record(NotificationEvent event, Outcome outcome, InboundMessage message) {
        if (!event.isDeliverOnce() || event.idempotencyKey() == null || event.idempotencyKey().isBlank()) {
            log.error("Cannot persist undelivered email without a deliver-once request id");
            return false;
        }
        try {
            int recorded = jdbc.update(RECORD_SQL, event.idempotencyKey(), event.getUserId(),
                    event.getOrganizationId(), RECORD_MARKER, outcome.status, replayPayload(event, message),
                    outcome.reason, event.getCorrelationId(), RECORD_MARKER);
            if (recorded == 0) {
                return false;
            }
            log.error("Deliver-once email remains undelivered: requestId={}", MessageIds.loggable(event.idempotencyKey()));
            alert(event.idempotencyKey());
            return true;
        } catch (Exception failure) {
            log.error("Could not record or alert for undelivered email: requestId={}",
                    MessageIds.loggable(event.idempotencyKey()), failure);
            return false;
        }
    }

    public boolean resolve(NotificationEvent event) {
        if (!event.isDeliverOnce() || event.idempotencyKey() == null
                || event.getRecipients() == null || event.getRecipients().isEmpty()) {
            return false;
        }
        return jdbc.update(RESOLVE_SQL, event.idempotencyKey(), RECORD_MARKER, event.idempotencyKey() + "#") == 1;
    }

    public int replay() {
        List<Map<String, Object>> rows = jdbc.queryForList(REPLAY_SQL,
                RECORD_MARKER, RETRIES_EXHAUSTED_REASON, maxReplays, REPLAY_BATCH_SIZE);
        int sent = 0;
        for (Map<String, Object> row : rows) {
            RequestContextInterceptor.setCurrentNotificationKey((String) row.get("request_id"));
            try {
                TransportMessage message = replayMessage((String) row.get("payload_json"));
                MessageIds origin = MessageIds.from(message.getApplicationProperties());
                RequestContextInterceptor.setCurrentCorrelationId(origin.correlationId());
                RequestContextInterceptor.setCurrentRequestId(origin.requestId());
                sender.sendMessage(message);
                sent++;
            } catch (Exception failure) {
                jdbc.update(REPLAY_FAILED_SQL, ((Number) row.get("id")).longValue());
                log.error("Failed to replay undelivered email: requestId={}",
                        MessageIds.loggable((String) row.get("request_id")), failure);
            } finally {
                RequestContextInterceptor.clearContext();
            }
        }
        return sent;
    }

    @Scheduled(fixedDelayString = "${notifier.delivery.replay-interval-ms:3600000}")
    public void replayDue() {
        try {
            replay();
        } catch (Exception failure) {
            log.error("Undelivered email replay sweep failed", failure);
        }
    }

    private String replayPayload(NotificationEvent event, InboundMessage message) throws Exception {
        NotificationEvent replay = event.toBuilder().build();
        replay.setRecipients(null);
        // A replay row is readable like any other record, so it never carries a token or auth link.
        replay.setTemplateFields(SecretFields.redact(event.getNotificationAction(), event.getTemplateFields()));
        ArrayNode payload = mapper.valueToTree(List.of(replay));
        ReplayMetadata.from(message).writeTo((ObjectNode) payload.get(0));
        return mapper.writeValueAsString(payload);
    }

    private TransportMessage replayMessage(String body) throws Exception {
        NotificationEvent event = mapper.readValue(body, NotificationEvent[].class)[0];
        TransportMessage message = new TransportMessage(MessageBody.fromString(body));
        ReplayMetadata.from(mapper.readTree(body)).writeTo(message);
        message.getApplicationProperties().put("notificationType", event.getNotificationType().name());
        if (event.getNotificationType() == NotificationType.ACCOUNT_EVENT) {
            message.getApplicationProperties().put("event", "account");
        }
        return message;
    }

    private double openCount() {
        try {
            return jdbc.queryForObject(OPEN_COUNT_SQL, Long.class, RECORD_MARKER, GAUGE_BATCH_SIZE);
        } catch (Exception failure) {
            log.error("Could not count undelivered emails", failure);
            return Double.NaN;
        }
    }

    /**
     * Tells every super admin once. The alert counts as sent once any of them has it, so a failure
     * for one admin never sends it again to the others; it is retried only when nobody got it.
     */
    private void alert(String requestId) {
        if (jdbc.update(CLAIM_ALERT_SQL, ALERT_CLAIMED, requestId, RECORD_MARKER, ALERT_CLAIMED) == 0) {
            return;
        }
        boolean told = false;
        try {
            told = alertSuperAdmins(requestId);
        } catch (Exception failure) {
            log.error("Could not alert super admins for undelivered email: requestId={}",
                    MessageIds.loggable(requestId), failure);
        }
        jdbc.update(SET_ALERT_SQL, told ? ALERT_SENT : null, requestId, ALERT_CLAIMED);
    }

    private boolean alertSuperAdmins(String requestId) {
        List<String> admins = roleEmailMapper.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null);
        if (admins.isEmpty()) {
            log.error("No active super admin can receive undelivered email alerts: requestId={}",
                    MessageIds.loggable(requestId));
            return false;
        }
        boolean told = false;
        for (String admin : admins) {
            try {
                emailProvider.sendTemplatedEmail(admin, ALERT_SUBJECT, RECORD_MARKER, Map.of("requestId", htmlEscape(requestId)));
                told = true;
            } catch (RuntimeException failure) {
                log.error("Could not alert a super admin for undelivered email: requestId={} failure={}",
                        MessageIds.loggable(requestId), SafeFailure.describe(failure));
            }
        }
        return told;
    }
}
