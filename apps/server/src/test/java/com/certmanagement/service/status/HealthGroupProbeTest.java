// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** The probe against a real HTTP server: what counts as up, the deadline, and what it never sends. */
class HealthGroupProbeTest {

    private static final Duration TIMEOUT = Duration.ofMillis(300);

    private final AtomicReference<Headers> lastRequestHeaders = new AtomicReference<>();
    private final HealthGroupProbe probe = new HealthGroupProbe(JsonMapper.builderWithJackson2Defaults().build(), TIMEOUT);
    private ExecutorService handlers;
    private HttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        handlers = Executors.newCachedThreadPool();
        server.setExecutor(handlers);
        server.createContext("/up", exchange -> {
            lastRequestHeaders.set(exchange.getRequestHeaders());
            respond(exchange, 200, "{\"status\":\"UP\"}");
        });
        server.createContext("/down", exchange -> respond(exchange, 503, "{\"status\":\"DOWN\"}"));
        server.createContext("/down-ok", exchange -> respond(exchange, 200, "{\"status\":\"DOWN\"}"));
        server.createContext("/lowercase", exchange -> respond(exchange, 200, "{\"status\":\"up\"}"));
        server.createContext("/not-json", exchange -> respond(exchange, 200, "<html>UP</html>"));
        server.createContext("/no-status", exchange -> respond(exchange, 200, "{\"groups\":[\"UP\"]}"));
        server.createContext("/array", exchange -> respond(exchange, 200, "[\"UP\"]"));
        server.createContext("/large", exchange -> respond(exchange, 200,
                "{\"status\":\"UP\",\"pad\":\"" + "x".repeat(HealthGroupProbe.MAX_BODY_BYTES) + "\"}"));
        server.createContext("/slow", exchange -> {
            sleep(TIMEOUT.multipliedBy(5));
            respond(exchange, 200, "{\"status\":\"UP\"}");
        });
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().set("Location", url("/up").toString());
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
        handlers.shutdownNow();
        MDC.clear();
    }

    @Test
    void upOnA2xxThatSaysUp() {
        assertThat(probe.isUp(url("/up"))).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/down", "/down-ok", "/lowercase", "/not-json", "/no-status", "/array", "/large",
            "/missing"})
    void anyOtherAnswerIsDown(String path) {
        assertThat(probe.isUp(url(path))).isFalse();
    }

    @Test
    void aRedirectIsNotFollowed() {
        assertThat(probe.isUp(url("/redirect"))).isFalse();
        assertThat(lastRequestHeaders.get()).isNull();
    }

    @Test
    void aSlowAnswerFailsWithinTheDeadline() {
        long started = System.nanoTime();

        boolean up = probe.isUp(url("/slow"));

        assertThat(up).isFalse();
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(TIMEOUT.multipliedBy(4));
    }

    @Test
    void aRefusedConnectionIsDown() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closedPort = socket.getLocalPort();
        }

        assertThat(probe.isUp(URI.create("http://127.0.0.1:" + closedPort + "/actuator/health/status"))).isFalse();
    }

    @Test
    void noTraceOrRequestHeadersAreForwarded() {
        MDC.put("requestId", "public-request-id");
        MDC.put("correlationId", "public-correlation-id");

        assertThat(probe.isUp(url("/up"))).isTrue();

        Headers sent = lastRequestHeaders.get();
        assertThat(sent.keySet()).map(String::toLowerCase)
                .doesNotContain("x-request-id", "x-correlation-id", "x-message-id", "traceparent", "authorization",
                        "cookie");
    }

    private URI url(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
