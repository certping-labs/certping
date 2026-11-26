// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.TransportMessage;
import com.certmanagement.controller.AgentGatewayController;
import com.certmanagement.controller.AgentGatewayController.GatewayMessage;
import com.certmanagement.controller.AgentGatewayController.SendRequest;
import com.certmanagement.controller.AgentGatewayController.SettleRequest;
import com.certmanagement.messaging.security.AgentMessageVerificationException;
import com.certmanagement.messaging.security.VerifiedAgentMessage;
import com.certmanagement.messaging.transport.AgentGatewayHeaders;
import com.certmanagement.messaging.transport.AgentTokenService;
import com.certmanagement.messaging.transport.PostgresMessageQueue;
import com.certmanagement.messaging.transport.PostgresMessageQueue.ReceivedMessage;
import com.certmanagement.messaging.transport.QueueInboundSenders;
import com.certmanagement.messaging.transport.TransportProperties;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The PostgreSQL transport end to end against a real database: the queue's lock semantics, agent
 * tokens, the gateway's tenant scoping, and the server worker that consumes agent results.
 */
@Testcontainers(disabledWithoutDocker = true)
class PostgresTransportPostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    private static JdbcTemplate jdbc;

    private TransportProperties props;
    private PostgresMessageQueue queue;
    private AgentTokenService tokens;
    private AgentGatewayController gateway;
    private long orgA;
    private long orgB;

    @BeforeAll
    static void migrate() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();
        jdbc = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM message_queue");
        jdbc.update("DELETE FROM agent_tokens");
        props = new TransportProperties();
        props.setLockDuration(Duration.ofSeconds(30));
        props.setMaxDeliveryCount(2);
        props.setMaxReceiveWait(Duration.ofSeconds(1));
        props.setInternalToken("internal-secret-for-tests");
        ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();
        queue = new PostgresMessageQueue(jdbc, mapper, props);
        tokens = new AgentTokenService(jdbc, props);
        gateway = new AgentGatewayController(queue, tokens, props);
        orgA = newOrg();
        orgB = newOrg();
    }

    private static long newOrg() {
        return jdbc.queryForObject("""
                INSERT INTO organizations (name, domain, slug, org_type, is_deleted)
                VALUES ('Org ' || md5(random()::text), md5(random()::text) || '.test',
                        'org-' || md5(random()::text), 'B2B', false)
                RETURNING id
                """, Long.class);
    }

    private static TransportMessage message(String id, String body, Map<String, Object> properties) {
        TransportMessage m = new TransportMessage(body);
        if (id != null) {
            m.setMessageId(id);
        }
        m.getApplicationProperties().putAll(properties);
        return m;
    }

    // ---- queue ---------------------------------------------------------------------------

    @Test
    void countWaitingCountsOneOrganizationsLiveMessagesUpToTheCap() {
        String org = AgentGatewayHeaders.ORGANIZATION_PROPERTY;
        for (int i = 0; i < 3; i++) {
            queue.send("out", message(null, "a" + i, Map.of(org, String.valueOf(orgA))));
        }
        queue.send("out", message(null, "b", Map.of(org, String.valueOf(orgB))));
        queue.receive("out", 1); // a locked message still waits

        assertThat(queue.countWaiting("out", orgA, 100) + queue.countWaiting("out", orgB, 100)).isEqualTo(4);
        assertThat(queue.countWaiting("out", orgA, 2)).isEqualTo(2);
        assertThat(queue.countWaiting("out", null, 100)).isEqualTo(4);
        assertThat(queue.countWaiting("elsewhere", orgA, 100)).isZero();
    }

    @Test
    void theGatewayRefusesASendOnceTheOrganizationsOutboundQueueIsFull() {
        props.setMaxWaitingMessagesPerOrganization(2);
        com.certmanagement.service.FixedWindowRateLimiter unlimited = org.mockito.Mockito.mock(
                com.certmanagement.service.FixedWindowRateLimiter.class);
        org.mockito.Mockito.when(unlimited.tryAcquire(anyString(), org.mockito.ArgumentMatchers.anyInt(), any()))
                .thenReturn(java.util.OptionalLong.empty());
        AgentGatewayController limited = new AgentGatewayController(queue, tokens, props,
                new com.certmanagement.messaging.transport.AgentGatewayLimits(props, unlimited, queue));
        String auth = "Bearer " + tokens.create(orgA, "agent", "test").plainToken();

        limited.send(auth, new SendRequest("outbound", null, "1", null, null, null));
        limited.send(auth, new SendRequest("outbound", null, "2", null, null, null));

        assertThatThrownBy(() -> limited.send(auth, new SendRequest("outbound", null, "3", null, null, null)))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS));
    }

    @Test
    void aTargetedMessageGoesOnlyToItsAgent() {
        queue.send("c1", message("t", "targeted", Map.of("TargetAgentTokenId", "7")));
        queue.send("c1", message("u", "untargeted", Map.of()));

        assertThat(queue.receive("c1", 5, 8L)).extracting(ReceivedMessage::body).containsExactly("untargeted");
        assertThat(queue.receive("c1", 5, 7L)).extracting(ReceivedMessage::body).containsExactly("targeted");
    }

    @Test
    void receiveLocksAMessageSoNoOtherReceiverGetsIt() {
        queue.send("c1", message("m1", "{\"a\":1}", Map.of("MessageType", "X", "Count", 3)));

        List<ReceivedMessage> first = queue.receive("c1", 5);
        assertThat(first).hasSize(1);
        ReceivedMessage m = first.get(0);
        assertThat(m.body()).isEqualTo("{\"a\":1}");
        assertThat(m.messageId()).isEqualTo("m1");
        assertThat(m.applicationProperties()).containsEntry("MessageType", "X").containsEntry("Count", 3);
        assertThat(m.deliveryCount()).isZero();
        assertThat(queue.receive("c1", 5)).isEmpty();

        assertThat(queue.complete("c1", m.id(), m.lockToken())).isTrue();
        assertThat(queue.complete("c1", m.id(), m.lockToken())).isFalse();
        assertThat(queue.depth("c1").values().stream().mapToLong(Long::longValue).sum()).isZero();
    }

    @Test
    void aRepeatedMessageIdIsIgnoredAndChannelsAreIsolated() {
        queue.send("c1", message("dup", "1", Map.of()));
        queue.send("c1", message("dup", "2", Map.of()));
        queue.send("c2", message("dup", "3", Map.of()));
        queue.send("c1", message(null, "4", Map.of()));

        assertThat(queue.receive("c1", 10)).extracting(ReceivedMessage::body).containsExactly("1", "4");
        assertThat(queue.receive("c2", 10)).extracting(ReceivedMessage::body).containsExactly("3");
    }

    @Test
    void abandonRedeliversUntilTheDeliveryLimitThenDeadLetters() {
        queue.send("c1", message("m", "x", Map.of()));

        ReceivedMessage first = queue.receive("c1", 1).get(0);
        assertThat(queue.abandon("c1", first.id(), first.lockToken())).isTrue();
        ReceivedMessage second = queue.receive("c1", 1).get(0);
        assertThat(second.deliveryCount()).isEqualTo(1);
        assertThat(second.lockToken()).isNotEqualTo(first.lockToken());
        assertThat(queue.abandon("c1", first.id(), first.lockToken())).as("stale lock").isFalse();
        assertThat(queue.abandon("c1", second.id(), second.lockToken())).isTrue();

        assertThat(queue.receive("c1", 1)).isEmpty();
        assertThat(jdbc.queryForObject("SELECT dead_reason FROM message_queue", String.class))
                .isEqualTo("MaxDeliveryCountExceeded");
    }

    @Test
    void deadLetterRenewAndWrongChannelSettlement() {
        queue.send("c1", message("m", "x", Map.of()));
        ReceivedMessage m = queue.receive("c1", 1).get(0);

        assertThat(queue.renewLock("c1", m.id(), m.lockToken())).isPresent();
        assertThat(queue.renewLock("c1", m.id(), UUID.randomUUID())).isEmpty();
        assertThat(queue.complete("other", m.id(), m.lockToken())).isFalse();
        assertThat(queue.deadLetter("c1", m.id(), m.lockToken(), "Bad", "why")).isTrue();
        assertThat(queue.depth("c1")).containsEntry("DEAD", 1L);
    }

    @Test
    void scheduledMessagesWaitAndExpiredOnesAreSweptAway() {
        TransportMessage later = message("later", "x", Map.of());
        later.setScheduledEnqueueTime(OffsetDateTime.now().plusHours(1));
        queue.send("c1", later);
        TransportMessage expiring = message("exp", "y", Map.of());
        expiring.setTimeToLive(Duration.ofMillis(1));
        queue.send("c1", expiring);
        jdbc.update("UPDATE message_queue SET expires_at = NOW() - INTERVAL '1 second' WHERE message_id = 'exp'");

        assertThat(queue.receive("c1", 10)).isEmpty();
        queue.sweep();
        assertThat(jdbc.queryForList("SELECT message_id FROM message_queue", String.class)).containsExactly("later");
    }

    @Test
    void sweepReleasesMessagesWhoseLockRanOut() {
        queue.send("c1", message("m", "x", Map.of()));
        queue.receive("c1", 1);
        jdbc.update("UPDATE message_queue SET locked_until = NOW() - INTERVAL '1 second'");

        queue.sweep();

        assertThat(queue.receive("c1", 1)).hasSize(1);
    }

    @Test
    void workerSweepReleasesExpiredLocks() {
        queue.send("c1", message("m", "x", Map.of()));
        queue.receive("c1", 1);
        jdbc.update("UPDATE message_queue SET locked_until = NOW() - INTERVAL '1 second'");

        new QueueAgentResponseWorker(queue, mock(CertResponseProcessor.class), props, JsonMapper.builderWithJackson2Defaults().build()).sweep();

        assertThat(queue.receive("c1", 1)).hasSize(1);
    }

    @Test
    void queueInboundSendersWriteToTheNamedQueue() {
        new QueueInboundSenders(queue).senderFor("7-agent-inbound").sendMessage(message("m", "x", Map.of()));
        assertThat(queue.receive("7-agent-inbound", 1)).hasSize(1);
    }

    // ---- tokens --------------------------------------------------------------------------

    @Test
    void tokensAuthenticateUntilRevoked() {
        AgentTokenService.CreatedToken created = tokens.create(orgA, "edge-1", "alice");
        assertThat(created.plainToken()).startsWith(AgentTokenService.TOKEN_PREFIX);
        assertThat(created.token().tokenPrefix()).isEqualTo(created.plainToken().substring(0, 10));
        assertThat(jdbc.queryForObject("SELECT token_hash FROM agent_tokens", String.class))
                .doesNotContain(created.plainToken());

        assertThat(tokens.authenticate(created.plainToken())).contains(orgA);
        assertThat(tokens.authenticate("cpa_wrong")).isEmpty();
        assertThat(tokens.authenticate("not-a-token")).isEmpty();
        assertThat(tokens.authenticate(null)).isEmpty();
        assertThat(tokens.list(orgA)).hasSize(1).first().satisfies(t -> assertThat(t.lastUsedAt()).isNotNull());

        assertThat(tokens.revoke(orgB, created.token().id())).as("other org").isFalse();
        assertThat(tokens.revoke(orgA, created.token().id())).isTrue();
        assertThat(tokens.authenticate(created.plainToken())).isEmpty();
    }

    @Test
    void bootstrapTokenIsRegisteredOnceForTheNamedOrganization() {
        String slug = jdbc.queryForObject("SELECT slug FROM organizations WHERE id = ?", String.class, orgB);
        String plain = "cpa_" + "b".repeat(40);
        props.setBootstrapAgentToken(plain);
        props.setBootstrapAgentOrganization(slug);

        tokens.registerBootstrapToken();
        tokens.registerBootstrapToken();

        assertThat(tokens.authenticate(plain)).contains(orgB);
        assertThat(tokens.list(orgB)).hasSize(1);
    }

    @Test
    void bootstrapTokenConnectsOnceItsOrganizationExists() {
        String plain = "cpa_" + "d".repeat(40);
        props.setBootstrapAgentToken(plain);
        props.setBootstrapAgentOrganization("created-later");
        tokens.onReady();

        assertThat(tokens.isPendingBootstrap(plain)).isTrue();
        assertThat(tokens.isPendingBootstrap("cpa_" + "e".repeat(40))).isFalse();
        assertThatThrownBy(() -> gateway.whoami("Bearer " + plain))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));

        long org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type, is_deleted) "
                + "VALUES ('Later', 'later.test', 'created-later', 'B2B', false) RETURNING id", Long.class);
        assertThat(tokens.authenticate(plain)).contains(org);
        assertThat(tokens.isPendingBootstrap(plain)).isFalse();

        // Revoked stays revoked: the bootstrap token is not silently registered again.
        tokens.revoke(org, tokens.list(org).get(0).id());
        assertThat(tokens.authenticate(plain)).isEmpty();
    }

    @Test
    void bootstrapTokenIsIgnoredWhenWeakOrTheOrganizationIsMissing() {
        props.setBootstrapAgentToken("cpa_short");
        tokens.registerBootstrapToken();
        props.setBootstrapAgentToken("cpa_" + "c".repeat(40));
        props.setBootstrapAgentOrganization("no-such-org");
        tokens.registerBootstrapToken();
        props.setBootstrapAgentToken("");
        tokens.registerBootstrapToken();

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM agent_tokens", Integer.class)).isZero();
    }

    // ---- gateway -------------------------------------------------------------------------

    @Test
    void agentsReadOnlyTheirOwnInboundQueue() throws Exception {
        String tokenA = "Bearer " + tokens.create(orgA, "a", null).plainToken();
        queue.send(props.inboundQueueFor(String.valueOf(orgA)), message("for-a", "a", Map.of()));
        queue.send(props.inboundQueueFor(String.valueOf(orgB)), message("for-b", "b", Map.of()));

        assertThat(gateway.whoami(tokenA)).containsEntry("organizationId", orgA).containsEntry("internal", false);
        List<GatewayMessage> got = gateway.receive(tokenA, null, 10, 0);
        assertThat(got).extracting(GatewayMessage::body).containsExactly("a");

        GatewayMessage m = got.get(0);
        assertThat(gateway.renewLock(tokenA, m.id(), null, new SettleRequest(m.lockToken(), null, null))
                .getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(gateway.complete(tokenA, m.id(), null, new SettleRequest(m.lockToken(), null, null))
                .getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(gateway.complete(tokenA, m.id(), null, new SettleRequest(m.lockToken(), null, null))
                .getStatusCode()).isEqualTo(HttpStatus.GONE);

        assertThatThrownBy(() -> gateway.receive(tokenA, "notifications", 1, 0))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void longPollReturnsEmptyAfterTheWait() throws Exception {
        String tokenA = "Bearer " + tokens.create(orgA, "a", null).plainToken();
        long start = System.nanoTime();
        assertThat(gateway.receive(tokenA, "inbound", 1, 1)).isEmpty();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isGreaterThanOrEqualTo(Duration.ofMillis(900));
    }

    @Test
    void sentResultsAreStampedWithTheTokensOrganization() throws Exception {
        String tokenA = "Bearer " + tokens.create(orgA, "a", null).plainToken();

        gateway.send(tokenA, new SendRequest("outbound", "r1", "{}",
                Map.of("MessageType", "AGENT_ERROR", AgentGatewayHeaders.ORGANIZATION_PROPERTY, "999"), null, 60L));
        gateway.send(tokenA, new SendRequest("inbound", "retry-1", "{}", Map.of("RetryCount", 1),
                OffsetDateTime.now().minusSeconds(1), null));

        ReceivedMessage result = queue.receive(props.getOutboundQueue(), 1).get(0);
        assertThat(result.applicationProperties())
                .containsEntry(AgentGatewayHeaders.ORGANIZATION_PROPERTY, String.valueOf(orgA))
                .containsEntry("MessageType", "AGENT_ERROR");
        assertThat(queue.receive(props.inboundQueueFor(String.valueOf(orgA)), 1)).hasSize(1);

        assertThatThrownBy(() -> gateway.send(tokenA, new SendRequest("notifications", null, "{}", null, null, null)))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> gateway.send(tokenA, new SendRequest("outbound", null, null, null, null, null)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void theInternalTokenReadsAndSendsNotificationsOnly() throws Exception {
        String internal = "Bearer internal-secret-for-tests";
        gateway.send(internal, new SendRequest("notifications", "n1", "{}", Map.of("notificationType", "SYSTEM_EVENT"),
                null, null));

        List<GatewayMessage> got = gateway.receive(internal, "notifications", 5, 0);
        assertThat(got).hasSize(1);
        assertThat(got.get(0).applicationProperties()).doesNotContainKey(AgentGatewayHeaders.ORGANIZATION_PROPERTY);
        GatewayMessage m = got.get(0);
        assertThat(gateway.abandon(internal, m.id(), null, new SettleRequest(m.lockToken(), null, null))
                .getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        GatewayMessage again = gateway.receive(internal, null, 5, 0).get(0);
        assertThat(gateway.deadLetter(internal, again.id(), null, new SettleRequest(again.lockToken(), "R", "d"))
                .getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        assertThatThrownBy(() -> gateway.send(internal, new SendRequest("outbound", null, "{}", null, null, null)))
                .isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> gateway.receive(internal, "inbound", 1, 0))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void requestsWithoutAValidTokenAreRejected() {
        assertThatThrownBy(() -> gateway.whoami(null)).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> gateway.whoami("Basic abc")).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> gateway.whoami("Bearer cpa_nope")).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> gateway.complete("Bearer internal-secret-for-tests", 1L, null,
                new SettleRequest(null, null, null))).isInstanceOf(ResponseStatusException.class);
    }

    // ---- server worker -------------------------------------------------------------------

    @Test
    void workerProcessesResultsAsVerifiedForTheStampedOrganization() {
        CertResponseProcessor processor = mock(CertResponseProcessor.class);
        doAnswer(inv -> {
            ((Runnable) inv.getArgument(3)).run();
            return null;
        }).when(processor).process(anyString(), anyString(), any(), any(), any());
        ReceivedMessage m = stamped("{\"organizationId\":\"" + orgA + "\"}", String.valueOf(orgA), "r");
        QueueAgentResponseWorker worker = new QueueAgentResponseWorker(queue, processor, props, JsonMapper.builderWithJackson2Defaults().build());
        try {
            worker.handle(m);
        } finally {
            worker.stop();
        }

        verify(processor).process(eq("CERT_ISSUANCE_RESPONSE"), anyString(),
                eq(new VerifiedAgentMessage(String.valueOf(orgA), "CERT_ISSUANCE_RESPONSE", "r",
                        jdbcEnqueued(), true)), any(), any());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM message_queue", Integer.class)).isZero();
    }

    // ---- Expiry, revoke, and the token recorded with each applied result ------------------

    @Test
    void anExpiredTokenGets401() throws Exception {
        AgentTokenService.CreatedToken created = tokens.create(orgA, "edge", "alice", OffsetDateTime.now().plusDays(30));
        String auth = "Bearer " + created.plainToken();
        assertThat(created.token().expiresAt()).isNotNull();
        assertThat(gateway.receive(auth, null, 1, 0)).isEmpty();

        jdbc.update("UPDATE agent_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE id = ?", created.token().id());

        assertThatThrownBy(() -> gateway.receive(auth, null, 1, 0))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
        assertThat(tokens.authenticate(created.plainToken())).isEmpty();
        AgentTokenService.CreatedToken past = tokens.create(orgA, "old", "alice", OffsetDateTime.now().minusMinutes(1));
        assertThatThrownBy(() -> gateway.whoami("Bearer " + past.plainToken()))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    void aRevokedTokenGets401OnItsNextPoll() throws Exception {
        AgentTokenService.CreatedToken created = tokens.create(orgA, "edge", "alice");
        String auth = "Bearer " + created.plainToken();
        assertThat(created.token().expiresAt()).as("no expiry unless asked").isNull();
        assertThat(gateway.receive(auth, null, 1, 0)).isEmpty();

        tokens.revoke(orgA, created.token().id());

        assertThatThrownBy(() -> gateway.receive(auth, null, 1, 0))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
    }

    @Test
    void theBootstrapTokenNeverExpires() {
        String plain = "cpa_" + "f".repeat(40);
        props.setBootstrapAgentToken(plain);
        props.setBootstrapAgentOrganization(null);
        tokens.registerBootstrapToken();

        long org = tokens.identify(plain).orElseThrow().organizationId();
        assertThat(tokens.list(org)).singleElement().satisfies(t -> assertThat(t.expiresAt()).isNull());
        props.setBootstrapAgentToken("");
    }

    @Test
    void eachAppliedResultRecordsTheTokenThatDeliveredIt() {
        jdbc.update("DELETE FROM agent_result_receipts");
        AgentTokenService.CreatedToken created = tokens.create(orgA, "edge", "alice");
        AgentTokenService.CreatedToken other = tokens.create(orgA, "lab", "alice");
        gateway.send("Bearer " + created.plainToken(), new SendRequest("outbound", "res-1",
                "{\"requestId\":\"req-9\",\"status\":\"ISSUED\"}",
                Map.of("MessageType", "CERT_ISSUANCE_RESPONSE",
                        AgentGatewayHeaders.AGENT_TOKEN_PROPERTY, String.valueOf(other.token().id())), null, null));
        ReceivedMessage result = queue.receive(props.getOutboundQueue(), 1).get(0);
        assertThat(result.applicationProperties()).as("the gateway's stamp, not the agent's claim")
                .containsEntry(AgentGatewayHeaders.AGENT_TOKEN_PROPERTY, String.valueOf(created.token().id()));

        CertResponseProcessor processor = mock(CertResponseProcessor.class);
        doAnswer(inv -> {
            ((Runnable) inv.getArgument(3)).run();
            return null;
        }).when(processor).process(anyString(), anyString(), any(), any(), any());
        com.certmanagement.messaging.transport.AgentResultReceipts receipts =
                new com.certmanagement.messaging.transport.AgentResultReceipts(jdbc);
        QueueAgentResponseWorker worker = new QueueAgentResponseWorker(queue, processor, props,
                JsonMapper.builderWithJackson2Defaults().build(), receipts);
        try {
            worker.handle(result);
        } finally {
            worker.stop();
        }

        assertThat(receipts.forRequest(orgA, "req-9")).singleElement().satisfies(r -> {
            assertThat(r.agentTokenId()).isEqualTo(created.token().id());
            assertThat(r.messageType()).isEqualTo("CERT_ISSUANCE_RESPONSE");
            assertThat(r.messageId()).isEqualTo("res-1");
        });
    }

    @Test
    void aResultTheProcessorDoesNotCompleteRecordsNothing() {
        jdbc.update("DELETE FROM agent_result_receipts");
        CertResponseProcessor processor = mock(CertResponseProcessor.class);
        doAnswer(inv -> {
            ((Runnable) inv.getArgument(4)).run();
            return null;
        }).when(processor).process(anyString(), anyString(), any(), any(), any());
        ReceivedMessage m = stamped("{\"requestId\":\"req-10\"}", String.valueOf(orgA), "r10");
        QueueAgentResponseWorker worker = new QueueAgentResponseWorker(queue, processor, props,
                JsonMapper.builderWithJackson2Defaults().build(),
                new com.certmanagement.messaging.transport.AgentResultReceipts(jdbc));
        try {
            worker.handle(m);
        } finally {
            worker.stop();
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM agent_result_receipts", Integer.class)).isZero();
    }

    @Test
    void workerFillsAMissingBodyOrganizationFromTheAuthenticatedStamp() {
        QueueAgentResponseWorker worker = new QueueAgentResponseWorker(queue, mock(CertResponseProcessor.class),
                props, JsonMapper.builderWithJackson2Defaults().build());
        assertThat(worker.withOrganization("{\"a\":1}", "7")).isEqualTo("{\"a\":1,\"organizationId\":\"7\"}");
        assertThat(worker.withOrganization("{\"organizationId\":null}", "7")).contains("\"7\"");
        assertThat(worker.withOrganization("{\"organizationId\":\"7\"}", "7")).isEqualTo("{\"organizationId\":\"7\"}");
        assertThat(worker.withOrganization("not json", "7")).isEqualTo("not json");
        assertThat(worker.withOrganization("[1]", "7")).isEqualTo("[1]");
    }

    @Test
    void workerDeadLettersUnstampedOrMismatchedResults() {
        CertResponseProcessor processor = mock(CertResponseProcessor.class);
        doThrow(AgentMessageVerificationException.rejected("BODY_ORGANIZATION_MISMATCH", "mismatch"))
                .when(processor).requireBodyOrganizationMatches(anyString(), any());
        ReceivedMessage unstamped = stamped("{}", null, "r1");
        ReceivedMessage mismatched = stamped("{\"organizationId\":\"" + orgB + "\"}", String.valueOf(orgA), "r2");
        QueueAgentResponseWorker worker = new QueueAgentResponseWorker(queue, processor, props, JsonMapper.builderWithJackson2Defaults().build());
        try {
            worker.handle(unstamped);
            assertThat(jdbc.queryForObject("SELECT dead_reason FROM message_queue WHERE message_id = 'r1'",
                    String.class)).isEqualTo("MissingOrganization");
            jdbc.update("DELETE FROM message_queue WHERE message_id = 'r1'");
            worker.handle(mismatched);
        } finally {
            worker.stop();
        }
        verify(processor, never()).process(any(), any(), any(), any(), any());
        assertThat(jdbc.queryForObject("SELECT dead_reason FROM message_queue", String.class))
                .isEqualTo("BODY_ORGANIZATION_MISMATCH");
    }

    @Test
    void workerAbandonsWhenProcessingThrows() {
        CertResponseProcessor processor = mock(CertResponseProcessor.class);
        doThrow(new IllegalStateException("db down")).when(processor)
                .process(anyString(), anyString(), any(), any(), any());
        ReceivedMessage m = stamped("{}", String.valueOf(orgA), "r");
        QueueAgentResponseWorker worker = new QueueAgentResponseWorker(queue, processor, props, JsonMapper.builderWithJackson2Defaults().build());
        try {
            worker.handle(m);
        } finally {
            worker.stop();
        }
        assertThat(jdbc.queryForObject("SELECT status FROM message_queue", String.class)).isEqualTo("READY");
        assertThat(worker.isRunning()).isFalse();
    }

    @Test
    void workerLifecycleStartsAndStopsItsPollers() {
        CertResponseProcessor processor = mock(CertResponseProcessor.class);
        QueueAgentResponseWorker worker = new QueueAgentResponseWorker(queue, processor, props, JsonMapper.builderWithJackson2Defaults().build());
        worker.start();
        worker.start();
        assertThat(worker.isRunning()).isTrue();
        worker.stop();
        assertThat(worker.isRunning()).isFalse();
    }

    private OffsetDateTime enqueued;

    private ReceivedMessage stamped(String body, String org, String id) {
        Map<String, Object> properties = org == null
                ? Map.of("MessageType", "CERT_ISSUANCE_RESPONSE")
                : Map.of("MessageType", "CERT_ISSUANCE_RESPONSE", AgentGatewayHeaders.ORGANIZATION_PROPERTY, org);
        queue.send(props.getOutboundQueue(), message(id, body, properties));
        ReceivedMessage m = queue.receive(props.getOutboundQueue(), 1).get(0);
        enqueued = m.enqueuedAt();
        return m;
    }

    private OffsetDateTime jdbcEnqueued() {
        return enqueued;
    }
}
