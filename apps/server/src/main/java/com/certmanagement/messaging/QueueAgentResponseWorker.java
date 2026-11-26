// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.security.AgentMessageVerificationException;
import com.certmanagement.messaging.security.VerifiedAgentMessage;
import com.certmanagement.messaging.transport.AgentGatewayHeaders;
import com.certmanagement.messaging.transport.AgentResultReceipts;
import org.springframework.beans.factory.annotation.Autowired;
import com.certmanagement.messaging.transport.PostgresMessageQueue;
import com.certmanagement.messaging.transport.PostgresMessageQueue.ReceivedMessage;
import com.certmanagement.messaging.transport.TransportProperties;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Consumes agent results from the PostgreSQL queue.
 *
 * <p>Agents put results on {@code cert-agent-outbound} through the gateway, which stamps the
 * organization of the token that sent them. That stamp is authenticated, so the message is
 * treated as verified for that organization, and a body naming any other organization is
 * dead-lettered rather than processed.
 *
 * <p>It also runs the queue's housekeeping: releasing expired locks, dropping expired messages and
 * purging old dead letters.
 */
@Slf4j
@Component
public class QueueAgentResponseWorker implements SmartLifecycle {

    private static final long IDLE_SLEEP_MS = 1000;

    private final PostgresMessageQueue queue;
    private final CertResponseProcessor processor;
    private final TransportProperties properties;
    private final ObjectMapper objectMapper;
    private final String channel;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final List<Thread> workers = new ArrayList<>();
    private ScheduledExecutorService lockRenewer;

    private final AgentResultReceipts receipts;

    /** A worker that records no receipts; for tests. */
    public QueueAgentResponseWorker(PostgresMessageQueue queue, CertResponseProcessor processor,
                                    TransportProperties properties,
                                    ObjectMapper objectMapper) {
        this(queue, processor, properties, objectMapper, null);
    }

    @Autowired
    public QueueAgentResponseWorker(PostgresMessageQueue queue, CertResponseProcessor processor,
                                    TransportProperties properties,
                                    ObjectMapper objectMapper, AgentResultReceipts receipts) {
        this.objectMapper = objectMapper;
        this.queue = queue;
        this.processor = processor;
        this.properties = properties;
        this.channel = properties.getOutboundQueue();
        this.receipts = receipts;
    }

    @Override
    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        int concurrency = Math.max(1, properties.getServerConsumerConcurrency());
        for (int i = 0; i < concurrency; i++) {
            Thread t = new Thread(this::loop, "agent-response-worker-" + i);
            t.setDaemon(true);
            t.start();
            workers.add(t);
        }
        // The broker's own housekeeping (lock expiry, TTL, dead-letter retention). It runs here rather
        // than as a registered job because the queue must keep working while jobs are paused.
        renewer().scheduleWithFixedDelay(this::sweep, 15, 15, TimeUnit.SECONDS);
        log.info("Agent response worker started: channel={}, concurrency={}", channel, concurrency);
    }

    @Override
    public void stop() {
        running.set(false);
        workers.forEach(Thread::interrupt);
        for (Thread t : workers) {
            try {
                t.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        workers.clear();
        synchronized (this) {
            if (lockRenewer != null) {
                lockRenewer.shutdownNow();
                lockRenewer = null;
            }
        }
    }

    private synchronized ScheduledExecutorService renewer() {
        if (lockRenewer == null) {
            lockRenewer = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "agent-response-lock-renewer");
                t.setDaemon(true);
                return t;
            });
        }
        return lockRenewer;
    }

    @Override
    public boolean isRunning() {
        return running.get();
    }

    private void loop() {
        while (running.get()) {
            try {
                List<ReceivedMessage> batch = queue.receive(channel, 1);
                if (batch.isEmpty()) {
                    Thread.sleep(IDLE_SLEEP_MS);
                    continue;
                }
                batch.forEach(this::handle);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (RuntimeException e) {
                log.warn("Agent response worker poll failed: {}", e.getMessage());
                sleepQuietly();
            }
        }
    }

    void handle(ReceivedMessage message) {
        Object type = message.applicationProperties().get("MessageType");
        String messageType = type == null ? null : type.toString();
        Object org = message.applicationProperties().get(AgentGatewayHeaders.ORGANIZATION_PROPERTY);
        if (org == null || org.toString().isBlank()) {
            queue.deadLetter(channel, message.id(), message.lockToken(), "MissingOrganization",
                    "Message did not come through the agent gateway");
            return;
        }
        Long tokenId = AgentResultReceipts.tokenId(
                message.applicationProperties().get(AgentGatewayHeaders.AGENT_TOKEN_PROPERTY));
        VerifiedAgentMessage verified = new VerifiedAgentMessage(org.toString(), messageType,
                message.messageId(), message.enqueuedAt(), true, tokenId);
        long renewEvery = Math.max(5, properties.getLockDuration().toSeconds() / 2);
        ScheduledFuture<?> renewal = renewer().scheduleAtFixedRate(
                () -> queue.renewLock(channel, message.id(), message.lockToken()),
                renewEvery, renewEvery, TimeUnit.SECONDS);
        MDC.put("orgId", verified.organizationId());
        MDC.put("msgId", String.valueOf(message.messageId()));
        try {
            try {
                processor.requireBodyOrganizationMatches(message.body(), verified);
            } catch (AgentMessageVerificationException e) {
                log.warn("Agent result rejected: reason={}, messageType={}, organizationId={}",
                        e.getReason(), messageType, verified.organizationId());
                queue.deadLetter(channel, message.id(), message.lockToken(), e.getReason(), e.getMessage());
                return;
            }
            log.info("Agent result received: channel={}, messageType={}, deliveryCount={}, messageId={}",
                    channel, messageType, message.deliveryCount(), message.messageId());
            String body = withOrganization(message.body(), verified.organizationId());
            processor.process(messageType, body, verified,
                    () -> {
                        recordReceipt(verified, tokenId, message, messageType, body);
                        queue.complete(channel, message.id(), message.lockToken());
                    },
                    () -> queue.abandon(channel, message.id(), message.lockToken()));
        } catch (RuntimeException e) {
            log.error("Agent result processing failed: messageType={}, messageId={}", messageType,
                    message.messageId(), e);
            queue.abandon(channel, message.id(), message.lockToken());
        } finally {
            renewal.cancel(false);
            MDC.remove("orgId");
            MDC.remove("msgId");
        }
    }

    /**
     * Records which agent token delivered an applied result. A failure to record is logged and
     * does not undo the result, which has already been applied.
     */
    private void recordReceipt(VerifiedAgentMessage verified, Long tokenId, ReceivedMessage message,
                               String messageType, String body) {
        if (receipts == null) {
            return;
        }
        try {
            receipts.record(new AgentResultReceipts.Receipt(Long.parseLong(verified.organizationId()), tokenId,
                    message.messageId(), messageType, requestId(body)));
        } catch (RuntimeException e) {
            log.error("Could not record the agent token of an applied result: messageType={}, messageId={}, tokenId={}",
                    messageType, message.messageId(), tokenId, e);
        }
    }

    private String requestId(String body) {
        try {
            JsonNode node = objectMapper.readTree(body);
            String id = node.path("requestId").asString("");
            return id.isBlank() ? null : id;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Handlers read the organization from the body. An agent that has not learned its
     * organization yet (it comes from the token) sends none; the gateway's stamp is authenticated,
     * so it fills the gap. A body naming another organization was already rejected above.
     */
    String withOrganization(String body, String organizationId) {
        try {
            JsonNode node = objectMapper.readTree(body);
            if (node instanceof ObjectNode object
                    && (!object.hasNonNull("organizationId") || object.path("organizationId").asString().isBlank())) {
                object.put("organizationId", organizationId);
                return objectMapper.writeValueAsString(object);
            }
        } catch (Exception ignored) {
            // Not a JSON object: handlers deal with it as before.
        }
        return body;
    }

    void sweep() {
        try {
            queue.sweep();
        } catch (RuntimeException e) {
            log.warn("Message queue sweep failed: {}", e.getMessage());
        }
    }

    private static void sleepQuietly() {
        try {
            Thread.sleep(IDLE_SLEEP_MS * 2);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
