// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.transport;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import tools.jackson.core.JacksonException;

/**
 * Client for the server's agent gateway, used by the notifier with the internal token ({@code /api/v1/agent-gateway}).
 *
 * <p>Only outbound HTTPS is used. {@code HTTPS_PROXY} (or {@code https_proxy}) is honoured, and
 * so are the JVM's standard {@code https.proxyHost} settings. A private CA can be trusted through
 * the JVM trust store as usual.
 */
public class GatewayClient {

    public static final String BASE_PATH = "/api/v1/agent-gateway";

    /** A message leased from the gateway, as the gateway returns it. */
    public record Leased(long id, UUID lockToken, String messageId, String body,
                         Map<String, Object> applicationProperties, int deliveryCount,
                         OffsetDateTime enqueuedAt, OffsetDateTime lockedUntil) {
    }

    /** {@link Leased} seen through the transport-neutral message interface. */
    public record LeasedMessage(Leased leased) implements InboundMessage {
        @Override public MessageBody getBody() {
            return MessageBody.fromString(leased.body() == null ? "" : leased.body());
        }
        @Override public Map<String, Object> getApplicationProperties() {
            return leased.applicationProperties() == null
                    ? new java.util.HashMap<>() : leased.applicationProperties();
        }
        @Override public String getMessageId() { return leased.messageId(); }
        @Override public long getDeliveryCount() { return leased.deliveryCount(); }
        @Override public OffsetDateTime getEnqueuedTime() { return leased.enqueuedAt(); }
        @Override public long getSequenceNumber() { return leased.id(); }
    }

    /** The gateway refused the call; {@code status} is the HTTP status. */
    public static class GatewayException extends RuntimeException {
        private final int status;
        private final Duration retryAfter;

        public GatewayException(int status, String message) {
            this(status, message, null);
        }

        public GatewayException(int status, String message, Duration retryAfter) {
            super(message);
            this.status = status;
            this.retryAfter = retryAfter;
        }

        public int getStatus() {
            return status;
        }

        /** The server's Retry-After header (sent with HTTP 429), or empty when it sent none. */
        public Optional<Duration> getRetryAfter() {
            return Optional.ofNullable(retryAfter);
        }
    }

    /** Attempts for a settle or send call the server throttles with HTTP 429. */
    static final int MAX_ATTEMPTS_WHEN_THROTTLED = 5;
    /** Wait between throttled attempts when the server sends no Retry-After. */
    static final Duration DEFAULT_RETRY_AFTER = Duration.ofSeconds(1);
    /** Longest wait honoured from a Retry-After header. */
    static final Duration MAX_RETRY_AFTER = Duration.ofSeconds(60);

    /** How long to wait after {@code e}: its Retry-After if present, else {@code fallback}, capped at 60 s. */
    public static Duration retryDelay(GatewayException e, Duration fallback) {
        Duration d = e.getRetryAfter().orElse(fallback == null ? DEFAULT_RETRY_AFTER : fallback);
        if (d.isNegative()) {
            return Duration.ZERO;
        }
        return d.compareTo(MAX_RETRY_AFTER) > 0 ? MAX_RETRY_AFTER : d;
    }

    /** Parses a Retry-After value given in seconds; an HTTP date or junk is ignored. */
    static Duration parseRetryAfter(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds < 0 ? null : Duration.ofSeconds(seconds);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private final URI base;
    private final String authorization;
    private final HttpClient http;
    private final ObjectMapper mapper;
    private final Duration requestTimeout;

    public GatewayClient(String serverUrl, String token, Duration requestTimeout, ObjectMapper mapper) {
        if (serverUrl == null || serverUrl.isBlank()) {
            throw new IllegalStateException("notifier.transport.server-url (CERTPING_SERVER_URL) is required");
        }
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("notifier.transport.token (CERTPING_INTERNAL_TOKEN) is required");
        }
        String trimmed = serverUrl.trim().replaceAll("/+$", "");
        this.base = URI.create(trimmed + BASE_PATH);
        this.authorization = "Bearer " + token.trim();
        this.mapper = mapper;
        this.requestTimeout = requestTimeout;
        this.http = buildHttpClient(System.getenv());
    }

    /** For tests: a prebuilt client. */
    GatewayClient(URI base, String token, Duration requestTimeout, ObjectMapper mapper, HttpClient http) {
        this.base = base;
        this.authorization = "Bearer " + token;
        this.mapper = mapper;
        this.requestTimeout = requestTimeout;
        this.http = http;
    }

    static HttpClient buildHttpClient(Map<String, String> env) {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10));
        proxyFrom(env).ifPresentOrElse(builder::proxy, () -> builder.proxy(ProxySelector.getDefault()));
        return builder.build();
    }

    static Optional<ProxySelector> proxyFrom(Map<String, String> env) {
        String value = env.getOrDefault("HTTPS_PROXY", env.get("https_proxy"));
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        URI uri = URI.create(value.contains("://") ? value : "http://" + value);
        if (uri.getHost() == null) {
            return Optional.empty();
        }
        int port = uri.getPort() > 0 ? uri.getPort() : 3128;
        return Optional.of(ProxySelector.of(new InetSocketAddress(uri.getHost(), port)));
    }

    public JsonNode whoami() {
        return send(get("/whoami", requestTimeout), 200);
    }

    public List<Leased> receive(int max, Duration wait) {
        String path = "/messages?queue=notifications&max=" + max + "&waitSeconds=" + wait.toSeconds();
        JsonNode node = send(get(path, requestTimeout.plus(wait)), 200);
        List<Leased> out = new ArrayList<>();
        if (node != null && node.isArray()) {
            for (JsonNode item : node) {
                out.add(mapper.convertValue(item, Leased.class));
            }
        }
        return out;
    }

    public boolean complete(Leased m) {
        return settle(m, "complete", null, null);
    }

    public boolean abandon(Leased m) {
        return settle(m, "abandon", null, null);
    }

    public boolean deadLetter(Leased m, String reason, String description) {
        return settle(m, "dead-letter", reason, description);
    }

    public boolean renewLock(Leased m) {
        return settle(m, "renew-lock", null, null);
    }

    /** Sends to {@code queue}; the notifier only sends "notifications" (scheduled retries and replays). */
    public void sendMessage(String queue, String messageId, String body, Map<String, Object> properties,
                            OffsetDateTime scheduledEnqueueTime, Duration timeToLive) {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("queue", queue);
        payload.put("messageId", messageId);
        payload.put("body", body);
        payload.set("applicationProperties", mapper.valueToTree(properties == null ? Map.of() : properties));
        if (scheduledEnqueueTime != null) {
            payload.put("scheduledEnqueueTime", scheduledEnqueueTime.toString());
        }
        if (timeToLive != null && !timeToLive.isZero() && !timeToLive.isNegative()) {
            payload.put("timeToLiveSeconds", Math.max(1, timeToLive.toSeconds()));
        }
        // A lost send loses a result, so a throttled send is retried rather than dropped.
        sendRetrying(post("/messages", payload), 202);
    }

    private boolean settle(Leased m, String action, String reason, String description) {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("lockToken", m.lockToken().toString());
        if (reason != null) {
            payload.put("reason", reason);
        }
        if (description != null) {
            payload.put("description", description);
        }
        try {
            // A lost complete causes a redelivery, so a throttled settle is retried rather than dropped.
            sendRetrying(post("/messages/" + m.id() + "/" + action + "?queue=notifications", payload), 200, 204);
            return true;
        } catch (GatewayException e) {
            if (e.getStatus() == 410) {
                return false; // lock lost: the message will be redelivered
            }
            throw e;
        }
    }

    private HttpRequest get(String path, Duration timeout) {
        return HttpRequest.newBuilder(URI.create(base + path))
                .timeout(timeout)
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .GET().build();
    }

    private HttpRequest post(String path, JsonNode payload) {
        try {
            return HttpRequest.newBuilder(URI.create(base + path))
                    .timeout(requestTimeout)
                    .header("Authorization", authorization)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload)))
                    .build();
        } catch (JacksonException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** {@link #send}, retried after the server's Retry-After while it answers HTTP 429. */
    private JsonNode sendRetrying(HttpRequest request, int... ok) {
        for (int attempt = 1; ; attempt++) {
            try {
                return send(request, ok);
            } catch (GatewayException e) {
                if (e.getStatus() != 429 || attempt >= MAX_ATTEMPTS_WHEN_THROTTLED) {
                    throw e;
                }
                try {
                    Thread.sleep(retryDelay(e, DEFAULT_RETRY_AFTER).toMillis());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    private JsonNode send(HttpRequest request, int... ok) {
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new GatewayException(0, "CertPing server unreachable at " + base + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GatewayException(0, "interrupted");
        }
        for (int code : ok) {
            if (response.statusCode() == code) {
                try {
                    String body = response.body();
                    return body == null || body.isBlank() ? null : mapper.readTree(body);
                } catch (JacksonException e) {
                    throw new GatewayException(response.statusCode(), "unreadable gateway response");
                }
            }
        }
        String hint = response.statusCode() == 401 ? " (check CERTPING_INTERNAL_TOKEN matches the server)" : "";
        Duration retryAfter = parseRetryAfter(response.headers().firstValue("Retry-After").orElse(null));
        throw new GatewayException(response.statusCode(),
                "agent gateway returned HTTP " + response.statusCode() + hint
                        + (retryAfter == null ? "" : " (retry after " + retryAfter.toSeconds() + "s)"), retryAfter);
    }
}
