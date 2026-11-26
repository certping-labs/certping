// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The HTTPS transport against a small in-process stand-in for the server's agent gateway. */
class HttpTransportTest {

    private final ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();
    private HttpServer server;
    private final ConcurrentLinkedQueue<Map<String, Object>> pending = new ConcurrentLinkedQueue<>();
    private final List<String> calls = new CopyOnWriteArrayList<>();
    private final List<JsonNode> posted = new CopyOnWriteArrayList<>();
    private volatile int settleStatus = 204;
    private volatile int receiveStatus = 200;
    /** The next this-many gateway calls (other than whoami) answer HTTP 429 with {@link #retryAfter}. */
    private final AtomicInteger throttled = new AtomicInteger();
    private volatile String retryAfter = "0";
    private GatewayClient client;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/agent-gateway", this::handle);
        server.start();
        client = new GatewayClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                + GatewayClient.BASE_PATH), "cpa_test", Duration.ofSeconds(5), mapper, HttpClient.newHttpClient());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath().substring(GatewayClient.BASE_PATH.length());
        String query = exchange.getRequestURI().getQuery();
        calls.add(exchange.getRequestMethod() + " " + path + (query == null ? "" : "?" + query));
        if (!"Bearer cpa_test".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
            respond(exchange, 401, "");
            return;
        }
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        if (!path.equals("/whoami") && throttled.getAndDecrement() > 0) {
            if (retryAfter != null) {
                exchange.getResponseHeaders().add("Retry-After", retryAfter);
            }
            respond(exchange, 429, "");
            return;
        }
        if (!body.isEmpty()) {
            posted.add(mapper.readTree(body));
        }
        if (path.equals("/whoami")) {
            respond(exchange, 200, "{\"organizationId\":\"42\",\"internal\":false}");
        } else if (path.equals("/messages") && exchange.getRequestMethod().equals("GET")) {
            if (receiveStatus != 200) {
                respond(exchange, receiveStatus, "");
                return;
            }
            Map<String, Object> next = pending.poll();
            respond(exchange, 200, mapper.writeValueAsString(next == null ? List.of() : List.of(next)));
        } else if (path.equals("/messages")) {
            respond(exchange, 202, "");
        } else {
            respond(exchange, settleStatus, path.endsWith("renew-lock") && settleStatus == 200
                    ? "{\"lockedUntil\":\"2030-01-01T00:00:00Z\"}" : "");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    private Map<String, Object> leased(long id, String body, OffsetDateTime lockedUntil) {
        return Map.of("id", id, "lockToken", UUID.randomUUID().toString(), "messageId", "m-" + id, "body", body,
                "applicationProperties", Map.of("MessageType", "CERT_ISSUANCE"), "deliveryCount", 0,
                "enqueuedAt", "2026-01-01T00:00:00Z", "lockedUntil", lockedUntil.toString());
    }

    @Test
    void receivesAndSettlesThroughTheGateway() {
        pending.add(leased(7, "{\"x\":1}", OffsetDateTime.now().plusMinutes(2)));

        List<GatewayClient.Leased> got = client.receive(1, Duration.ZERO);
        assertThat(got).hasSize(1);
        GatewayClient.LeasedMessage message = new GatewayClient.LeasedMessage(got.get(0));
        assertThat(message.getBody().toString()).isEqualTo("{\"x\":1}");
        assertThat(message.getApplicationProperties()).containsEntry("MessageType", "CERT_ISSUANCE");
        assertThat(message.getMessageId()).isEqualTo("m-7");
        assertThat(message.getSequenceNumber()).isEqualTo(7);
        assertThat(message.getDeliveryCount()).isZero();
        assertThat(message.getEnqueuedTime()).isNotNull();
        assertThat(message.getCorrelationId()).isNull();
        assertThat(message.getSubject()).isNull();

        assertThat(client.complete(got.get(0))).isTrue();
        assertThat(client.abandon(got.get(0))).isTrue();
        assertThat(client.deadLetter(got.get(0), "R", "d")).isTrue();
        settleStatus = 410;
        assertThat(client.renewLock(got.get(0))).as("lost lock").isFalse();
        settleStatus = 500;
        assertThatThrownBy(() -> client.complete(got.get(0))).isInstanceOf(GatewayClient.GatewayException.class);

        assertThat(calls).contains("POST /messages/7/complete?queue=notifications", "POST /messages/7/dead-letter?queue=notifications");
        assertThat(posted).anySatisfy(p -> assertThat(p.path("reason").asString()).isEqualTo("R"));
    }

    @Test
    void whoamiAndBadTokensReportClearly() {
        assertThat(client.whoami().path("organizationId").asString()).isEqualTo("42");
        GatewayClient wrong = new GatewayClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                + GatewayClient.BASE_PATH), "cpa_other", Duration.ofSeconds(5), mapper, HttpClient.newHttpClient());
        assertThatThrownBy(wrong::whoami).isInstanceOf(GatewayClient.GatewayException.class)
                .hasMessageContaining("401").satisfies(e ->
                        assertThat(((GatewayClient.GatewayException) e).getStatus()).isEqualTo(401));
    }

    @Test
    void unreachableServerIsAGatewayException() {
        GatewayClient down = new GatewayClient(URI.create("http://127.0.0.1:9" + GatewayClient.BASE_PATH),
                "cpa_test", Duration.ofSeconds(2), mapper, HttpClient.newHttpClient());
        assertThatThrownBy(down::whoami).isInstanceOf(GatewayClient.GatewayException.class)
                .hasMessageContaining("unreachable");
    }

    @Test
    void senderPostsResultsAndScheduledRetries() {
        TransportMessage result = new TransportMessage(MessageBody.fromString("{\"r\":1}"));
        result.setMessageId("res-1");
        result.getApplicationProperties().put("MessageType", "AGENT_ERROR");
        result.setTimeToLive(Duration.ofMinutes(5));
        HttpMessageSender outbound = new HttpMessageSender(client, "outbound");
        outbound.sendMessage(result);

        TransportMessage retry = new TransportMessage(MessageBody.fromString("{}"));
        retry.setScheduledEnqueueTime(OffsetDateTime.parse("2030-01-01T00:00:00Z"));
        new HttpMessageSender(client, "inbound").sendMessage(retry);

        assertThat(outbound.getEntityPath()).isEqualTo("agent-gateway/outbound");
        assertThat(posted).hasSize(2);
        assertThat(posted.get(0).path("queue").asString()).isEqualTo("outbound");
        assertThat(posted.get(0).path("messageId").asString()).isEqualTo("res-1");
        assertThat(posted.get(0).path("timeToLiveSeconds").asLong()).isEqualTo(300);
        assertThat(posted.get(0).path("applicationProperties").path("MessageType").asString()).isEqualTo("AGENT_ERROR");
        assertThat(posted.get(1).path("queue").asString()).isEqualTo("inbound");
        assertThat(posted.get(1).path("scheduledEnqueueTime").asString()).startsWith("2030-01-01");
    }

    @Test
    void consumerDeliversToTheListenerAndKeepsPolling() throws Exception {
        pending.add(leased(1, "{}", OffsetDateTime.now().plusSeconds(12)));
        pending.add(leased(2, "{}", OffsetDateTime.now().plusSeconds(12)));
        CountDownLatch delivered = new CountDownLatch(2);
        List<String> seen = Collections.synchronizedList(new ArrayList<>());
        HttpInboundConsumer consumer = new HttpInboundConsumer(client, context -> {
            seen.add(context.getMessage().getMessageId() + "@" + context.getEntityPath());
            context.complete();
            delivered.countDown();
        }, 1, Duration.ZERO, Duration.ofMinutes(1));

        consumer.start();
        consumer.start();
        try {
            assertThat(delivered.await(10, TimeUnit.SECONDS)).isTrue();
            assertThat(consumer.isRunning()).isTrue();
        } finally {
            consumer.close();
        }
        assertThat(consumer.isRunning()).isFalse();
        assertThat(seen).containsExactly("m-1@agent-gateway/notifications", "m-2@agent-gateway/notifications");
        assertThat(calls).contains("POST /messages/1/complete?queue=notifications", "POST /messages/2/complete?queue=notifications");
    }

    @Test
    void aFailingListenerAbandonsAndALongOneRenewsTheLock() {
        HttpInboundConsumer consumer = new HttpInboundConsumer(client, context -> {
            if (context.getMessage().getMessageId().equals("m-1")) {
                throw new IllegalStateException("boom");
            }
            try {
                Thread.sleep(6500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            context.deadLetter(new DeadLetterOptions().setDeadLetterReason("Bad"));
        }, 1, Duration.ZERO, Duration.ofMinutes(1));
        receiveStatus = 503; // keep the background poller from taking anything
        consumer.start();
        try {
            consumer.dispatch(new GatewayClient.Leased(1, UUID.randomUUID(), "m-1", "{}", null, 0, null,
                    OffsetDateTime.now().plusSeconds(10)));
            consumer.dispatch(new GatewayClient.Leased(2, UUID.randomUUID(), "m-2", "{}", null, 0, null,
                    OffsetDateTime.now().plusSeconds(10)));
        } finally {
            consumer.stop();
        }
        assertThat(calls).contains("POST /messages/1/abandon?queue=notifications",
                "POST /messages/2/renew-lock?queue=notifications", "POST /messages/2/dead-letter?queue=notifications");
    }

    @Test
    void pollersBackOffWhileTheServerFails() throws Exception {
        receiveStatus = 503;
        HttpInboundConsumer consumer = new HttpInboundConsumer(client, context -> { }, 1, Duration.ZERO, null);
        consumer.start();
        Thread.sleep(300);
        consumer.stop();
        // One receive, then a 1 second back-off: a failed receive must not retry straight away.
        assertThat(calls).filteredOn(c -> c.startsWith("GET /messages")).hasSize(1);
    }

    @Test
    void extraMessagesFromTheServerAreAbandonedAtOnce() throws Exception {
        GatewayClient gateway = mock(GatewayClient.class);
        GatewayClient.Leased m1 = new GatewayClient.Leased(1, UUID.randomUUID(), "m-1", "{}", null, 0, null,
                OffsetDateTime.now().plusSeconds(10));
        GatewayClient.Leased m2 = new GatewayClient.Leased(2, UUID.randomUUID(), "m-2", "{}", null, 0, null,
                OffsetDateTime.now().plusSeconds(10));
        GatewayClient.Leased m3 = new GatewayClient.Leased(3, UUID.randomUUID(), "m-3", "{}", null, 0, null,
                OffsetDateTime.now().plusSeconds(10));
        AtomicInteger receives = new AtomicInteger();
        when(gateway.receive(org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.any()))
                .thenAnswer(inv -> {
                    if (receives.getAndIncrement() == 0) {
                        return List.of(m1, m2, m3); // more than the max=1 the poller asked for
                    }
                    Thread.sleep(50);
                    return List.of();
                });
        List<GatewayClient.Leased> abandoned = new CopyOnWriteArrayList<>();
        when(gateway.abandon(org.mockito.ArgumentMatchers.any())).thenAnswer(inv -> {
            abandoned.add(inv.getArgument(0));
            return true;
        });
        List<String> seen = new CopyOnWriteArrayList<>();
        List<Integer> abandonedWhenListenerRan = new CopyOnWriteArrayList<>();
        CountDownLatch done = new CountDownLatch(1);
        HttpInboundConsumer consumer = new HttpInboundConsumer(gateway, context -> {
            seen.add(context.getMessage().getMessageId());
            abandonedWhenListenerRan.add(abandoned.size());
            context.complete();
            done.countDown();
        }, 1, Duration.ZERO, Duration.ofMinutes(1));
        when(gateway.complete(org.mockito.ArgumentMatchers.any())).thenReturn(true);

        consumer.start();
        try {
            assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
            Thread.sleep(200);
        } finally {
            consumer.stop();
        }
        verify(gateway, org.mockito.Mockito.atLeastOnce()).receive(1, Duration.ZERO);
        assertThat(seen).as("only the requested message is handled").containsExactly("m-1");
        assertThat(abandoned).containsExactlyInAnyOrder(m2, m3);
        assertThat(abandonedWhenListenerRan).as("extras go back before the first is worked on").containsExactly(2);
    }

    @Test
    void lockRenewalStartsAtReceipt() throws Exception {
        GatewayClient gateway = mock(GatewayClient.class);
        CountDownLatch renewed = new CountDownLatch(1);
        when(gateway.renewLock(org.mockito.ArgumentMatchers.any())).thenAnswer(inv -> {
            renewed.countDown();
            return true;
        });
        HttpInboundConsumer consumer = new HttpInboundConsumer(gateway, context -> {
            try {
                // The renewal scheduled at receipt fires while the listener is still working.
                assertThat(renewed.await(8, TimeUnit.SECONDS)).isTrue();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, 1, Duration.ZERO, Duration.ofMinutes(1));
        when(gateway.receive(org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.any()))
                .thenThrow(new GatewayClient.GatewayException(503, "not ready"));
        consumer.start();
        try {
            consumer.handle(List.of(new GatewayClient.Leased(4, UUID.randomUUID(), "m-4", "{}", null, 0, null,
                    OffsetDateTime.now().plusSeconds(10))));
        } finally {
            consumer.stop();
        }
        verify(gateway, org.mockito.Mockito.atLeastOnce()).renewLock(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void throttledPollsWaitForRetryAfterInsteadOfBackingOff() throws Exception {
        retryAfter = "0";
        throttled.set(3);
        HttpInboundConsumer consumer = new HttpInboundConsumer(client, context -> { }, 1, Duration.ZERO, null);
        consumer.start();
        Thread.sleep(500);
        consumer.stop();
        // With the doubling back-off the second poll would come only after 1 s.
        assertThat(calls).filteredOn(c -> c.startsWith("GET /messages")).hasSizeGreaterThan(3);
    }

    @Test
    void retryAfterIsExposedAndCapped() {
        retryAfter = "7";
        throttled.set(1);
        assertThatThrownBy(() -> client.receive(1, Duration.ZERO))
                .isInstanceOfSatisfying(GatewayClient.GatewayException.class, e -> {
                    assertThat(e.getStatus()).isEqualTo(429);
                    assertThat(e.getRetryAfter()).contains(Duration.ofSeconds(7));
                    assertThat(GatewayClient.retryDelay(e, Duration.ofSeconds(2))).isEqualTo(Duration.ofSeconds(7));
                });
        GatewayClient.GatewayException slow = new GatewayClient.GatewayException(429, "x", Duration.ofMinutes(5));
        assertThat(GatewayClient.retryDelay(slow, null)).isEqualTo(Duration.ofSeconds(60));
        GatewayClient.GatewayException none = new GatewayClient.GatewayException(429, "x");
        assertThat(none.getRetryAfter()).isEmpty();
        assertThat(GatewayClient.retryDelay(none, null)).isEqualTo(Duration.ofSeconds(1));
        assertThat(GatewayClient.parseRetryAfter("Wed, 21 Oct 2015 07:28:00 GMT")).isNull();
        assertThat(GatewayClient.parseRetryAfter("-1")).isNull();
    }

    @Test
    void throttledSettlesAndSendsAreRetried() {
        GatewayClient.Leased m = new GatewayClient.Leased(8, UUID.randomUUID(), "m-8", "{}", null, 0, null, null);
        retryAfter = "0";
        throttled.set(2);
        assertThat(client.complete(m)).isTrue();
        assertThat(calls).filteredOn(c -> c.equals("POST /messages/8/complete?queue=notifications")).hasSize(3);

        throttled.set(4);
        assertThat(client.renewLock(m)).isTrue();
        throttled.set(1);
        assertThat(client.abandon(m)).isTrue();
        throttled.set(1);
        assertThat(client.deadLetter(m, "R", "d")).isTrue();
        throttled.set(2);
        new HttpMessageSender(client, "notifications").sendMessage(new TransportMessage("{\"r\":1}"));
        assertThat(posted).anySatisfy(p -> assertThat(p.path("queue").asString()).isEqualTo("notifications"));

        throttled.set(100);
        assertThatThrownBy(() -> client.complete(m)).as("gives up after 5 attempts")
                .isInstanceOfSatisfying(GatewayClient.GatewayException.class,
                        e -> assertThat(e.getStatus()).isEqualTo(429));
        assertThat(throttled.get()).isEqualTo(95);
    }

    @Test
    void throttledSettleHonoursTheDefaultWaitWithoutAHeader() {
        GatewayClient.Leased m = new GatewayClient.Leased(9, UUID.randomUUID(), "m-9", "{}", null, 0, null, null);
        retryAfter = null;
        throttled.set(1);
        long start = System.nanoTime();
        assertThat(client.complete(m)).isTrue();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isGreaterThanOrEqualTo(Duration.ofMillis(900));
    }

    @Test
    void lostLockOnCompleteIsReported() {
        settleStatus = 410;
        GatewayClient.Leased m = new GatewayClient.Leased(3, UUID.randomUUID(), "m-3", null, null, 0, null, null);
        HttpInboundConsumer.HttpInboundContext context = new HttpInboundConsumer.HttpInboundContext(client, m);
        assertThat(context.getMessage().getBody().toString()).isEmpty();
        assertThat(context.getMessage().getApplicationProperties()).isEmpty();
        assertThatThrownBy(context::complete).isInstanceOf(IllegalStateException.class);
        context.abandon();
        context.deadLetter(null);
    }

    @Test
    void proxyComesFromTheEnvironment() {
        assertThat(GatewayClient.proxyFrom(Map.of())).isEmpty();
        assertThat(GatewayClient.proxyFrom(Map.of("HTTPS_PROXY", "proxy.corp:8080"))).isPresent();
        assertThat(GatewayClient.proxyFrom(Map.of("https_proxy", "http://proxy.corp"))).isPresent();
        assertThat(GatewayClient.proxyFrom(Map.of("HTTPS_PROXY", " "))).isEmpty();
        assertThat(GatewayClient.buildHttpClient(Map.of("HTTPS_PROXY", "proxy.corp:8080")).proxy()).isPresent();
        assertThat(GatewayClient.buildHttpClient(Map.of())).isNotNull();
    }

    @Test
    void publicConstructorRequiresUrlAndToken() {
        assertThatThrownBy(() -> new GatewayClient(" ", "cpa_x", Duration.ofSeconds(1), mapper))
                .hasMessageContaining("CERTPING_SERVER_URL");
        assertThatThrownBy(() -> new GatewayClient("https://x", null, Duration.ofSeconds(1), mapper))
                .hasMessageContaining("CERTPING_INTERNAL_TOKEN");
        assertThat(new GatewayClient("https://certping.example.com/", "cpa_x", Duration.ofSeconds(1), mapper))
                .isNotNull();
    }
}
