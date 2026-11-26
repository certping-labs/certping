// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.model.NotificationEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * One notification record per recipient of a deliver-once event, claimed before its send and
 * completed only by the claim that sent it. The record's request id is the event's plus a hash of
 * the address, so the partial unique index on {@code request_id} makes the claim atomic across
 * consumers. A PENDING record younger than the lease is another consumer's live claim.
 */
@Component
class RecipientClaims {

    /** Set on a record whose expired claim this claim took over: its first send may have gone out. */
    static final String LEASE_TAKEN_OVER = "LEASE_TAKEN_OVER";

    private static final String CLAIM = """
            INSERT INTO notification_records (request_id, email, user_id, organization_id, template_name, subject,
                                              sent_by, integration_type, status, payload_json, correlation_id,
                                              created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'EMAIL', 'PENDING', ?, ?, clock_timestamp(), clock_timestamp())
            ON CONFLICT (request_id) WHERE request_id IS NOT NULL DO UPDATE
            SET status = 'PENDING', subject = EXCLUDED.subject, payload_json = EXCLUDED.payload_json,
                failure_reason = CASE WHEN notification_records.status = 'PENDING' THEN ? END,
                updated_at = clock_timestamp()
            WHERE (notification_records.status = 'FAILED'
                   AND notification_records.failure_reason IS DISTINCT FROM 'PERMANENT_FAILURE')
               OR (notification_records.status = 'PENDING'
                   AND notification_records.updated_at < clock_timestamp() - make_interval(secs => ?))
            RETURNING id, updated_at, failure_reason""";

    private static final String HELD = """
            SELECT status, failure_reason, updated_at + make_interval(secs => ?) AS lease_ends
            FROM notification_records WHERE request_id = ?""";

    private static final String DELIVERED = """
            UPDATE notification_records SET status = 'DELIVERED', failure_reason = NULL, sent_at = clock_timestamp(),
                                            updated_at = clock_timestamp()
            WHERE id = ? AND status = 'PENDING' AND updated_at = ?""";

    private static final String FAILED = """
            UPDATE notification_records SET status = 'FAILED', failure_reason = ?, updated_at = clock_timestamp()
            WHERE id = ? AND status = 'PENDING' AND updated_at = ?""";

    private final JdbcTemplate jdbc;
    private final Duration lease;

    RecipientClaims(JdbcTemplate jdbc, @Value("${notifier.delivery.claim-lease:PT5M}") Duration lease) {
        this.jdbc = jdbc;
        this.lease = lease;
    }

    Duration lease() {
        return lease;
    }

    /** The claim this consumer holds on one recipient; {@code claimedAt} is its fence. */
    record Claim(long id, OffsetDateTime claimedAt, long claimedNanos, boolean takenOver) {
    }

    sealed interface Outcome permits Claimed, AlreadyDelivered, Held, Permanent {
    }

    record Claimed(Claim claim) implements Outcome {
    }

    record AlreadyDelivered() implements Outcome {
    }

    /** Another consumer's claim is live until {@code leaseEnds}. */
    record Held(OffsetDateTime leaseEnds) implements Outcome {
    }

    record Permanent() implements Outcome {
    }

    Outcome claim(NotificationEvent event, String recipient, String templateName, String subject, String payloadJson) {
        String requestId = recipientRequestId(event.idempotencyKey(), recipient);
        List<Claim> won = jdbc.query(CLAIM, (rs, n) -> new Claim(rs.getLong("id"),
                        rs.getObject("updated_at", OffsetDateTime.class), System.nanoTime(),
                        LEASE_TAKEN_OVER.equals(rs.getString("failure_reason"))),
                requestId, recipient, event.getUserId(), event.getOrganizationId(), templateName, subject,
                event.getSource(), payloadJson, event.getCorrelationId(), LEASE_TAKEN_OVER, lease.toSeconds());
        if (!won.isEmpty()) {
            return new Claimed(won.get(0));
        }
        return jdbc.query(HELD, rs -> {
            if (!rs.next()) {
                throw new IllegalStateException("recipient record " + requestId + " neither claimed nor present");
            }
            if ("DELIVERED".equals(rs.getString("status"))) {
                return new AlreadyDelivered();
            }
            if (UndeliveredEmailService.PERMANENT_FAILURE.equals(rs.getString("failure_reason"))) {
                return new Permanent();
            }
            return new Held(rs.getObject("lease_ends", OffsetDateTime.class));
        }, lease.toSeconds(), requestId);
    }

    /** True only when this claim still owned the record: a consumer that took it over keeps it. */
    boolean markDelivered(Claim claim) {
        return jdbc.update(DELIVERED, claim.id(), claim.claimedAt()) == 1;
    }

    boolean markFailed(Claim claim, String reason) {
        return jdbc.update(FAILED, reason, claim.id(), claim.claimedAt()) == 1;
    }

    /** The record key of one recipient: the address never appears in it, only its hash. */
    static String recipientRequestId(String requestId, String recipient) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(recipient.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
            return requestId + "#" + HexFormat.of().formatHex(digest, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
