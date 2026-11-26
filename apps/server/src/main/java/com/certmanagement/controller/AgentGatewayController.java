// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.messaging.transport.AgentGatewayHeaders;
import com.certmanagement.messaging.transport.AgentGatewayLimits;
import org.springframework.beans.factory.annotation.Autowired;
import com.certmanagement.messaging.transport.AgentTokenService;
import com.certmanagement.messaging.transport.PollBackoff;
import com.certmanagement.messaging.transport.PostgresMessageQueue;
import com.certmanagement.messaging.transport.PostgresMessageQueue.ReceivedMessage;
import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.messaging.transport.TransportProperties;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * HTTPS gateway between agents (and the notifier) and the PostgreSQL message queue.
 *
 * <p>Agents only ever make outbound HTTPS calls, so they work behind NAT, firewalls and corporate
 * proxies with no inbound port. The calls are the usual broker operations: receive with a lock,
 * then complete, abandon, dead-letter or renew the lock.
 *
 * <p>Callers authenticate with a bearer token:
 * <ul>
 *   <li>an agent token ({@code cpa_...}): the caller may read only its organization's inbound
 *       queue, and everything it sends is stamped with that organization;</li>
 *   <li>the internal token ({@code certping.transport.internal-token}): used by the notifier to
 *       read the notifications channel.</li>
 * </ul>
 */
@Slf4j
@RestController
@RequestMapping(AgentGatewayHeaders.BASE_PATH)
@Tag(name = "Agent Gateway", description = "Message transport for agents and the notifier (agent-token auth)")
public class AgentGatewayController {

    private static final int MAX_BODY_CHARS = 4 * 1024 * 1024;

    private final PostgresMessageQueue queue;
    private final AgentTokenService tokens;
    private final TransportProperties properties;
    /** Null only in tests that build the controller without limits. */
    private final AgentGatewayLimits limits;

    public AgentGatewayController(PostgresMessageQueue queue, AgentTokenService tokens,
                                  TransportProperties properties) {
        this(queue, tokens, properties, null);
    }

    @Autowired
    public AgentGatewayController(PostgresMessageQueue queue, AgentTokenService tokens,
                                  TransportProperties properties, AgentGatewayLimits limits) {
        this.queue = queue;
        this.tokens = tokens;
        this.properties = properties;
        this.limits = limits;
    }

    /**
     * Who is calling: an agent of one organization, or the internal notifier. {@code tokenKey} is a hash of
     * an agent's token, the key of its limits; null for the notifier, which is not limited.
     */
    record Caller(Long organizationId, boolean internal, String tokenKey, Long tokenId) {
        Caller(Long organizationId, boolean internal) {
            this(organizationId, internal, null, null);
        }
    }

    public record GatewayMessage(long id, UUID lockToken, String messageId, String body,
                                 Map<String, Object> applicationProperties, int deliveryCount,
                                 OffsetDateTime enqueuedAt, OffsetDateTime lockedUntil) {
        static GatewayMessage of(ReceivedMessage m) {
            return new GatewayMessage(m.id(), m.lockToken(), m.messageId(), m.body(), m.applicationProperties(),
                    m.deliveryCount(), m.enqueuedAt(), m.lockedUntil());
        }
    }

    public record SendRequest(String queue, String messageId, String body, Map<String, Object> applicationProperties,
                              OffsetDateTime scheduledEnqueueTime, Long timeToLiveSeconds) {
    }

    public record SettleRequest(UUID lockToken, String reason, String description) {
    }

    @GetMapping("/whoami")
    @Operation(summary = "Checks a token and returns the queues it can use")
    public Map<String, Object> whoami(@RequestHeader(value = "Authorization", required = false) String authorization) {
        Caller caller = authenticate(authorization);
        Map<String, Object> out = new HashMap<>();
        out.put("internal", caller.internal());
        out.put("organizationId", caller.organizationId());
        out.put("receiveQueue", channelFor(caller, null));
        return out;
    }

    @GetMapping("/messages")
    @Operation(summary = "Long-polls for messages and locks them")
    public List<GatewayMessage> receive(@RequestHeader(value = "Authorization", required = false) String authorization,
                                        @RequestParam(value = "queue", required = false) String queueName,
                                        @RequestParam(value = "max", defaultValue = "1") int max,
                                        @RequestParam(value = "waitSeconds", defaultValue = "20") int waitSeconds)
            throws InterruptedException {
        Caller caller = authenticate(authorization, AgentGatewayLimits.RequestKind.POLL);
        String channel = channelFor(caller, queueName);
        long wait = Math.min(Math.max(0, waitSeconds), properties.getMaxReceiveWait().toSeconds());
        long deadline = nanoClock.getAsLong() + Duration.ofSeconds(wait).toNanos();
        // Never hand back more than was asked for, whatever the queue returned.
        int limit = Math.max(1, max);
        PollBackoff backoff = new PollBackoff(properties.getPollCheckMin(), properties.getPollCheckMax());
        try (AgentGatewayLimits.PollSlot ignored = openPoll(caller)) {
            while (true) {
                List<ReceivedMessage> received = queue.receive(channel, limit,
                        caller.internal() ? null : caller.tokenId());
                long remainingNanos = deadline - nanoClock.getAsLong();
                if (!received.isEmpty() || remainingNanos <= 0) {
                    return received.stream().limit(limit).map(GatewayMessage::of).toList();
                }
                // The pause grows while the queue stays empty, but never runs past the caller's wait.
                long remainingMillis = Math.max(1, Duration.ofNanos(remainingNanos).toMillis());
                sleeper.sleep(Math.min(backoff.nextPauseMillis(), remainingMillis));
            }
        }
    }

    /** Sleeps between queue checks; replaced in tests. */
    @FunctionalInterface
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    private Sleeper sleeper = Thread::sleep;
    private java.util.function.LongSupplier nanoClock = System::nanoTime;

    /** For tests: a fake clock and sleeper. */
    void useClock(java.util.function.LongSupplier nanoClock, Sleeper sleeper) {
        this.nanoClock = nanoClock;
        this.sleeper = sleeper;
    }

    private AgentGatewayLimits.PollSlot openPoll(Caller caller) {
        if (limits == null || caller.internal()) {
            return () -> { };
        }
        return limits.openPoll(caller.tokenKey());
    }

    @PostMapping("/messages/{id}/complete")
    public ResponseEntity<Void> complete(@RequestHeader(value = "Authorization", required = false) String authorization,
                                         @PathVariable long id, @RequestParam(value = "queue", required = false) String queueName,
                                         @RequestBody SettleRequest request) {
        String channel = channelFor(authenticate(authorization), queueName);
        return settled(queue.complete(channel, id, requireLock(request)));
    }

    @PostMapping("/messages/{id}/abandon")
    public ResponseEntity<Void> abandon(@RequestHeader(value = "Authorization", required = false) String authorization,
                                        @PathVariable long id, @RequestParam(value = "queue", required = false) String queueName,
                                        @RequestBody SettleRequest request) {
        String channel = channelFor(authenticate(authorization), queueName);
        return settled(queue.abandon(channel, id, requireLock(request)));
    }

    @PostMapping("/messages/{id}/dead-letter")
    public ResponseEntity<Void> deadLetter(@RequestHeader(value = "Authorization", required = false) String authorization,
                                           @PathVariable long id, @RequestParam(value = "queue", required = false) String queueName,
                                           @RequestBody SettleRequest request) {
        String channel = channelFor(authenticate(authorization), queueName);
        return settled(queue.deadLetter(channel, id, requireLock(request),
                request.reason() == null ? "DeadLetteredByReceiver" : request.reason(), request.description()));
    }

    @PostMapping("/messages/{id}/renew-lock")
    public ResponseEntity<Map<String, Object>> renewLock(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable long id, @RequestParam(value = "queue", required = false) String queueName,
            @RequestBody SettleRequest request) {
        String channel = channelFor(authenticate(authorization), queueName);
        Optional<OffsetDateTime> until = queue.renewLock(channel, id, requireLock(request));
        return until.<ResponseEntity<Map<String, Object>>>map(t -> ResponseEntity.ok(Map.of("lockedUntil", t)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.GONE).build());
    }

    @PostMapping("/messages")
    @Operation(summary = "Sends a message: an agent result (outbound), a retry to the agent's own queue (inbound), "
            + "or a notification retry (internal callers)")
    public ResponseEntity<Void> send(@RequestHeader(value = "Authorization", required = false) String authorization,
                                     @RequestBody SendRequest request) {
        Caller caller = authenticate(authorization);
        if (request == null || request.body() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "body is required");
        }
        if (request.body().length() > MAX_BODY_CHARS) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "message body is too large");
        }
        String target = request.queue() == null ? "outbound" : request.queue();
        String channel;
        if (caller.internal()) {
            if (!"notifications".equals(target)) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "internal callers may only send notifications");
            }
            channel = properties.getNotificationsChannel();
        } else if ("outbound".equals(target)) {
            channel = properties.getOutboundQueue();
            if (limits != null) {
                // The outbound channel is shared: count only this organization's waiting messages.
                limits.checkQueueRoom(channel, caller.organizationId());
            }
        } else if ("inbound".equals(target)) {
            channel = properties.inboundQueueFor(String.valueOf(caller.organizationId()));
            if (limits != null) {
                limits.checkQueueRoom(channel, null);
            }
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "queue must be 'outbound' or 'inbound'");
        }

        TransportMessage message = new TransportMessage(request.body());
        if (request.messageId() != null && !request.messageId().isBlank()) {
            message.setMessageId(request.messageId());
        }
        if (request.applicationProperties() != null) {
            message.getApplicationProperties().putAll(request.applicationProperties());
        }
        if (!caller.internal()) {
            // The token, not the payload, decides who the message is from.
            message.getApplicationProperties().put(AgentGatewayHeaders.ORGANIZATION_PROPERTY,
                    String.valueOf(caller.organizationId()));
            // And which token: the server records it with every result it applies (agent_result_receipts).
            message.getApplicationProperties().put(AgentGatewayHeaders.AGENT_TOKEN_PROPERTY,
                    String.valueOf(caller.tokenId()));
            if (message.getApplicationProperties().containsKey(AgentGatewayHeaders.TARGET_AGENT_TOKEN_PROPERTY)) {
                message.getApplicationProperties().put(AgentGatewayHeaders.TARGET_AGENT_TOKEN_PROPERTY,
                        String.valueOf(caller.tokenId()));
            }
        } else {
            message.getApplicationProperties().remove(AgentGatewayHeaders.AGENT_TOKEN_PROPERTY);
        }
        if (request.scheduledEnqueueTime() != null) {
            message.setScheduledEnqueueTime(request.scheduledEnqueueTime());
        }
        if (request.timeToLiveSeconds() != null && request.timeToLiveSeconds() > 0) {
            message.setTimeToLive(Duration.ofSeconds(request.timeToLiveSeconds()));
        }
        queue.send(channel, message);
        return ResponseEntity.accepted().build();
    }

    private String channelFor(Caller caller, String requested) {
        if (caller.internal()) {
            if (requested != null && !requested.isBlank() && !"notifications".equals(requested)) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "internal callers read only notifications");
            }
            return properties.getNotificationsChannel();
        }
        if (requested != null && !requested.isBlank() && !"inbound".equals(requested)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "agents read only their inbound queue");
        }
        return properties.inboundQueueFor(String.valueOf(caller.organizationId()));
    }

    /** Authenticates a settle, send or whoami call (the higher rate limit). */
    Caller authenticate(String authorization) {
        return authenticate(authorization, AgentGatewayLimits.RequestKind.SETTLE);
    }

    Caller authenticate(String authorization, AgentGatewayLimits.RequestKind kind) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "bearer token required");
        }
        String token = authorization.substring(7).trim();
        String internal = properties.getInternalToken();
        if (internal != null && !internal.isBlank() && MessageDigest.isEqual(
                internal.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8))) {
            return new Caller(null, true);
        }
        // Revoked and expired tokens are refused here, on every call: the next poll gets 401.
        Optional<AgentTokenService.Identity> identity = tokens.identify(token);
        if (identity.isPresent()) {
            Caller caller = new Caller(identity.get().organizationId(), false, AgentGatewayLimits.keyOf(token),
                    identity.get().tokenId());
            if (limits != null) {
                limits.countRequest(caller.tokenKey(), kind);
            }
            return caller;
        }
        if (tokens.isPendingBootstrap(token)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "no organization yet: create one in CertPing and the bundled agent connects");
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid or revoked token");
    }

    private static UUID requireLock(SettleRequest request) {
        if (request == null || request.lockToken() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "lockToken is required");
        }
        return request.lockToken();
    }

    private static ResponseEntity<Void> settled(boolean ok) {
        // 410: the lock expired or the message was already settled; the receiver should drop it.
        return ok ? ResponseEntity.noContent().build() : ResponseEntity.status(HttpStatus.GONE).build();
    }
}
