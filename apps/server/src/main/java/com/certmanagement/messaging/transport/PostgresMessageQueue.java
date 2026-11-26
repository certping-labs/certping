// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;

import java.sql.Types;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The message queue: broker-style queue semantics on one PostgreSQL table.
 *
 * <ul>
 *   <li><b>Receive</b> locks up to N ready messages with {@code FOR UPDATE SKIP LOCKED}, so any
 *       number of receivers can share a channel without seeing the same message twice.</li>
 *   <li><b>Lock</b>: a received message belongs to its receiver until {@code locked_until}; the
 *       receiver renews it while it works and settles it with complete, abandon or dead-letter.
 *       A lock that runs out puts the message back.</li>
 *   <li><b>Scheduled delivery</b>: a message with a scheduled enqueue time stays invisible until
 *       then, which is how agents retry later without holding a worker.</li>
 *   <li><b>Dead-lettering</b> after {@code maxDeliveryCount} deliveries or on request. Dead
 *       messages stay for inspection and are purged after a retention period.</li>
 *   <li><b>Duplicate detection</b> on the sender's message id within a channel.</li>
 * </ul>
 *
 * Delivery is at least once: handlers must be idempotent.
 */
@Slf4j
public class PostgresMessageQueue {

    private static final TypeReference<Map<String, Object>> PROPERTIES = new TypeReference<>() { };

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final TransportProperties properties;

    public PostgresMessageQueue(JdbcTemplate jdbc, ObjectMapper objectMapper, TransportProperties properties) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    /** A message handed to a receiver, with the lock token it must present to settle it. */
    public record ReceivedMessage(long id, UUID lockToken, String channel, String messageId, String body,
                                  Map<String, Object> applicationProperties, int deliveryCount,
                                  OffsetDateTime enqueuedAt, OffsetDateTime lockedUntil) {
    }

    /** Enqueues {@code message} on {@code channel}; a repeated message id on the channel is ignored. */
    public void send(String channel, TransportMessage message) {
        // A message that is not scheduled for later is available at the database's NOW(), the clock receive
        // compares with. Taking it from this JVM's clock made a message sent a moment ahead of the database
        // clock (a skewed host, a paused VM) invisible to the next receive, so it lost its place in the order.
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime scheduledAt = message.getScheduledEnqueueTime() != null
                && message.getScheduledEnqueueTime().isAfter(now) ? message.getScheduledEnqueueTime() : null;
        Duration ttl = message.getTimeToLive();
        Double ttlSeconds = ttl != null && !ttl.isZero() && !ttl.isNegative() ? ttl.toNanos() / 1e9 : null;
        String messageId = message.getMessageId();
        jdbc.update("""
                INSERT INTO message_queue (channel, message_id, body, properties, available_at, expires_at, priority)
                VALUES (?, ?, ?, ?::jsonb, COALESCE(?::timestamptz, NOW()),
                        COALESCE(?::timestamptz, NOW()) + make_interval(secs => ?::double precision), ?)
                ON CONFLICT (channel, message_id) WHERE message_id IS NOT NULL DO NOTHING
                """,
                channel, messageId == null || messageId.isBlank() ? null : messageId,
                message.getBody().toString(), toJson(message.getApplicationProperties()),
                new SqlParameterValue(Types.TIMESTAMP_WITH_TIMEZONE, scheduledAt),
                new SqlParameterValue(Types.TIMESTAMP_WITH_TIMEZONE, scheduledAt),
                new SqlParameterValue(Types.DOUBLE, ttlSeconds),
                priorityOf(message));
    }

    /** Message types received ahead of the rest of their channel. */
    static final java.util.Set<String> PRIORITY_MESSAGE_TYPES = java.util.Set.of("CERT_DEPLOYMENT");

    /**
     * 1 for deployment commands, so a deployment of an already issued certificate does not wait behind a burst
     * of issuance commands on the same organization channel; 0 for everything else.
     */
    static int priorityOf(TransportMessage message) {
        Object type = message.getApplicationProperties().get("MessageType");
        return type != null && PRIORITY_MESSAGE_TYPES.contains(type.toString()) ? 1 : 0;
    }

    /**
     * How many messages of {@code channel} are waiting (ready or locked), counting at most {@code cap}: those
     * sent by {@code organizationId}'s agents ({@link AgentGatewayHeaders#ORGANIZATION_PROPERTY}), or all of
     * them when it is null. Bounded by the cap, and read from {@code ix_message_queue_channel_org_waiting}.
     */
    public int countWaiting(String channel, Long organizationId, int cap) {
        Integer count;
        if (organizationId == null) {
            count = jdbc.queryForObject("""
                    SELECT COUNT(*) FROM (SELECT 1 FROM message_queue
                                           WHERE channel = ? AND status <> 'DEAD' LIMIT ?) waiting
                    """, Integer.class, channel, cap);
        } else {
            count = jdbc.queryForObject("""
                    SELECT COUNT(*) FROM (SELECT 1 FROM message_queue
                                           WHERE channel = ? AND status <> 'DEAD'
                                             AND (properties ->> '%s') = ? LIMIT ?) waiting
                    """.formatted(AgentGatewayHeaders.ORGANIZATION_PROPERTY),
                    Integer.class, channel, String.valueOf(organizationId), cap);
        }
        return count == null ? 0 : count;
    }

    /**
     * Locks and returns up to {@code max} ready messages of {@code channel}: higher priority first, then oldest
     * first.
     *
     * <p>The rows are picked in a MATERIALIZED CTE, never in {@code WHERE id IN (SELECT ... LIMIT ?)}: with a
     * generic plan made while the queue was nearly empty PostgreSQL can run that form as a semi join that re-runs
     * the subquery per outer row, and one receive with a limit of 1 then leased every ready message. A
     * materialized CTE is evaluated exactly once, so the LIMIT holds whatever the plan.
     */
    public List<ReceivedMessage> receive(String channel, int max) {
        return receive(channel, max, null);
    }

    /**
     * As {@link #receive(String, int)} for one agent: a message targeted at another agent's token
     * ({@link AgentGatewayHeaders#TARGET_AGENT_TOKEN_PROPERTY}) is left for that agent.
     */
    public List<ReceivedMessage> receive(String channel, int max, Long callerTokenId) {
        int limit = Math.max(1, Math.min(max, properties.getMaxReceiveBatch()));
        String target = callerTokenId == null ? "" : """
                       AND (properties ->> '%s' IS NULL OR properties ->> '%s' = '%d')
                """.formatted(AgentGatewayHeaders.TARGET_AGENT_TOKEN_PROPERTY,
                AgentGatewayHeaders.TARGET_AGENT_TOKEN_PROPERTY, callerTokenId);
        List<Object[]> rows = jdbc.query("""
                WITH picked AS MATERIALIZED (
                    SELECT id FROM message_queue
                     WHERE channel = ? AND status = 'READY' AND available_at <= NOW()
                       AND (expires_at IS NULL OR expires_at > NOW())
                %s
                     ORDER BY priority DESC, available_at, id
                     LIMIT ?
                     FOR UPDATE SKIP LOCKED)
                UPDATE message_queue m
                   SET status = 'LEASED', delivery_count = m.delivery_count + 1, lock_token = gen_random_uuid(),
                       locked_until = NOW() + make_interval(secs => ?), updated_at = NOW()
                  FROM picked
                 WHERE m.id = picked.id
                RETURNING m.id, m.lock_token, m.channel, m.message_id, m.body, m.properties::text AS properties,
                          m.delivery_count, m.enqueued_at, m.locked_until, m.priority, m.available_at
                """.formatted(target), (rs, rowNum) -> new Object[] {rowMapper().mapRow(rs, rowNum), rs.getInt("priority"),
                        rs.getObject("available_at", OffsetDateTime.class)},
                channel, limit, properties.getLockDuration().toSeconds());
        // UPDATE ... RETURNING does not keep the CTE's order, so restore it here.
        List<ReceivedMessage> leased = rows.stream()
                .sorted(java.util.Comparator.<Object[]>comparingInt(r -> -(Integer) r[1])
                        .thenComparing(r -> (OffsetDateTime) r[2])
                        .thenComparingLong(r -> ((ReceivedMessage) r[0]).id()))
                .map(r -> (ReceivedMessage) r[0])
                .limit(limit)
                .toList();
        if (rows.size() > limit) {
            log.error("Message queue receive leased {} rows on channel {} with a limit of {}", rows.size(), channel, limit);
        }
        return leased;
    }

    /** Removes a settled message. False when the lock was lost (the message may be redelivered). */
    public boolean complete(String channel, long id, UUID lockToken) {
        return jdbc.update("DELETE FROM message_queue WHERE id = ? AND channel = ? AND lock_token = ? AND status = 'LEASED'",
                id, channel, lockToken) == 1;
    }

    /** Releases a message for redelivery now, or dead-letters it once its deliveries are used up. */
    public boolean abandon(String channel, long id, UUID lockToken) {
        return jdbc.update("""
                UPDATE message_queue
                   SET status = CASE WHEN delivery_count >= ? THEN 'DEAD' ELSE 'READY' END,
                       dead_reason = CASE WHEN delivery_count >= ? THEN 'MaxDeliveryCountExceeded' END,
                       lock_token = NULL, locked_until = NULL, updated_at = NOW()
                 WHERE id = ? AND channel = ? AND lock_token = ? AND status = 'LEASED'
                """, properties.getMaxDeliveryCount(), properties.getMaxDeliveryCount(), id, channel, lockToken) == 1;
    }

    public boolean deadLetter(String channel, long id, UUID lockToken, String reason, String description) {
        return jdbc.update("""
                UPDATE message_queue
                   SET status = 'DEAD', dead_reason = ?, dead_description = ?,
                       lock_token = NULL, locked_until = NULL, updated_at = NOW()
                 WHERE id = ? AND channel = ? AND lock_token = ? AND status = 'LEASED'
                """, truncate(reason, 200), description, id, channel, lockToken) == 1;
    }

    /** Extends a lock the caller still holds; empty when it was already lost. */
    public Optional<OffsetDateTime> renewLock(String channel, long id, UUID lockToken) {
        List<OffsetDateTime> renewed = jdbc.queryForList("""
                UPDATE message_queue SET locked_until = NOW() + make_interval(secs => ?), updated_at = NOW()
                 WHERE id = ? AND channel = ? AND lock_token = ? AND status = 'LEASED'
                RETURNING locked_until
                """, OffsetDateTime.class, properties.getLockDuration().toSeconds(), id, channel, lockToken);
        return renewed.stream().findFirst();
    }

    /**
     * Puts messages whose lock ran out back on the queue (or dead-letters them), drops expired
     * messages, and purges dead letters past their retention.
     */
    public void sweep() {
        int released = jdbc.update("""
                UPDATE message_queue
                   SET status = CASE WHEN delivery_count >= ? THEN 'DEAD' ELSE 'READY' END,
                       dead_reason = CASE WHEN delivery_count >= ? THEN 'MaxDeliveryCountExceeded' END,
                       lock_token = NULL, locked_until = NULL, updated_at = NOW()
                 WHERE status = 'LEASED' AND locked_until < NOW()
                """, properties.getMaxDeliveryCount(), properties.getMaxDeliveryCount());
        int expired = jdbc.update("DELETE FROM message_queue WHERE status = 'READY' AND expires_at < NOW()");
        int purged = jdbc.update("DELETE FROM message_queue WHERE status = 'DEAD' AND updated_at < NOW() - make_interval(secs => ?)",
                properties.getDeadLetterRetention().toSeconds());
        if (released + expired + purged > 0) {
            log.info("Message queue sweep: lockExpired={}, messageExpired={}, deadLettersPurged={}",
                    released, expired, purged);
        }
    }

    /** Ready, locked and dead message counts of {@code channel}, for health and support. */
    public Map<String, Long> depth(String channel) {
        Map<String, Long> depth = new LinkedHashMap<>();
        depth.put("READY", 0L);
        depth.put("LEASED", 0L);
        depth.put("DEAD", 0L);
        jdbc.query("SELECT status, COUNT(*) FROM message_queue WHERE channel = ? GROUP BY status",
                rs -> { depth.put(rs.getString(1), rs.getLong(2)); }, channel);
        return depth;
    }

    private RowMapper<ReceivedMessage> rowMapper() {
        return (rs, rowNum) -> new ReceivedMessage(
                rs.getLong("id"),
                rs.getObject("lock_token", UUID.class),
                rs.getString("channel"),
                rs.getString("message_id"),
                rs.getString("body"),
                fromJson(rs.getString("properties")),
                // Counts earlier deliveries: zero on the first.
                rs.getInt("delivery_count") - 1,
                rs.getObject("enqueued_at", OffsetDateTime.class),
                rs.getObject("locked_until", OffsetDateTime.class));
    }

    private String toJson(Map<String, Object> applicationProperties) {
        try {
            Map<String, Object> values = new LinkedHashMap<>();
            applicationProperties.forEach((key, value) -> values.put(key,
                    value instanceof OffsetDateTime time ? time.toString() : value));
            return objectMapper.writeValueAsString(values);
        } catch (Exception e) {
            throw new IllegalArgumentException("Application properties are not serializable", e);
        }
    }

    private Map<String, Object> fromJson(String json) {
        try {
            return json == null ? new LinkedHashMap<>() : objectMapper.readValue(json, PROPERTIES);
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
