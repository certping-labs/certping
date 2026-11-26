// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Settings of the message transport between the server, its agents and the notifier.
 *
 * <p>Messages live in the server's {@code message_queue} table and agents and the notifier pull
 * them over HTTPS from the agent gateway. Nothing but PostgreSQL is needed, so it suits Docker
 * Compose, a single server and Kubernetes alike.
 *
 * <p>The channel names below are stored on every queued row, so changing one strands the messages
 * already queued under the old name.
 */
@Data
@Component
@ConfigurationProperties(prefix = "certping.transport")
public class TransportProperties {

    /**
     * Per-organization agent inbound channel. {@code {orgId}} is replaced with the organization id.
     * The agent of organization X reads only {@code X-agent-inbound}.
     */
    private String inboundQueuePattern = "{orgId}-agent-inbound";

    /** Shared channel every agent sends its results to; the server's own consumer reads it. */
    private String outboundQueue = "cert-agent-outbound";

    /** Channel the notifier reads. */
    private String notificationsChannel = "notifications";

    /**
     * Time to live of {@code CERT_DISCOVERY} commands. A scan request an offline agent has not
     * picked up by then expires on the queue instead of running hours later against a feature or
     * credential that may since have been switched off; the scan row is cleared by its owner.
     */
    private Duration discoveryCommandTtl = Duration.ofHours(1);

    /** How long a received message stays locked to its receiver before it is offered again. */
    private Duration lockDuration = Duration.ofMinutes(2);

    /** Deliveries after which a message is dead-lettered. */
    private int maxDeliveryCount = 10;

    /** Upper bound for how long a receive call waits for a message (long polling). */
    private Duration maxReceiveWait = Duration.ofSeconds(25);

    /** Most messages one receive call returns. */
    private int maxReceiveBatch = 10;

    /** Long-polls one agent token may hold open at once (per server); one more is answered 429. */
    private int maxConcurrentPollsPerToken = 8;

    /**
     * Receive (poll) calls one agent token may make per minute, counted across pods in Redis; then 429 with
     * Retry-After. Only receives count here: settle and send calls have {@link #maxSettleRequestsPerTokenPerMinute}.
     */
    private int maxRequestsPerTokenPerMinute = 1200;

    /**
     * Complete, abandon, dead-letter, renew-lock, send and whoami calls one agent token may make per minute.
     * Much higher than the receive limit, because a deployment burst legitimately settles and sends many
     * messages; it only stops a runaway loop.
     */
    private int maxSettleRequestsPerTokenPerMinute = 6000;

    /**
     * Shortest pause between queue checks of one long poll, used right after a message was found. While the
     * queue stays empty the pause doubles up to {@link #pollCheckMax}; a found message resets it.
     */
    private Duration pollCheckMin = Duration.ofMillis(250);

    /** Longest pause between queue checks of one long poll while the queue stays empty. */
    private Duration pollCheckMax = Duration.ofSeconds(2);

    /**
     * Messages one organization may have waiting (ready or locked) on the outbound channel, and on its own
     * inbound channel through the gateway; a send over it is answered 429 until the server drains them.
     */
    private int maxWaitingMessagesPerOrganization = 10_000;

    /**
     * Largest request body the gateway accepts, checked before it is read (Content-Length) and while it is
     * read (chunked bodies); a larger one is answered 413.
     */
    private long maxRequestBodyBytes = 8L * 1024 * 1024;

    /** How long dead-lettered messages are kept for inspection before they are purged. */
    private Duration deadLetterRetention = Duration.ofDays(14);

    /** Messages the server's own consumer (agent responses) handles at once. */
    private int serverConsumerConcurrency = 4;

    /**
     * Shared secret the notifier presents to the gateway. Required for email delivery; empty
     * disables notifier access.
     */
    private String internalToken = "";

    /**
     * An agent token to register at startup, for single-server installs where the bundled agent
     * should work without a manual step. Bound to {@link #bootstrapAgentOrganization}.
     */
    private String bootstrapAgentToken = "";

    /** Slug of the organization the bootstrap agent token belongs to. */
    private String bootstrapAgentOrganization = "";

    /** Resolves the per-organization agent inbound channel for the given organization id. */
    public String inboundQueueFor(String organizationId) {
        if (organizationId == null || organizationId.isBlank()) {
            throw new IllegalArgumentException("organizationId must not be blank when resolving inbound queue name");
        }
        return inboundQueuePattern.replace("{orgId}", organizationId);
    }
}
