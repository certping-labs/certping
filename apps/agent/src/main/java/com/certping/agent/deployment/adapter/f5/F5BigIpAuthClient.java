// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

/**
 * BIG-IP iControl REST authentication + token lifecycle.
 *
 * Split out so the same auth logic can be reused by both deployment and discovery flows.
 */
@Slf4j
class F5BigIpAuthClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(60);

    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final String username;
    private final String password;
    private final HttpClient http;

    private String token;
    private Instant tokenExpiry;

    F5BigIpAuthClient(ObjectMapper objectMapper,
                      String host,
                      int port,
                      String username,
                      String password,
                      boolean verifySsl) {
        this(objectMapper,
                "https://" + host + ":" + port,
                username,
                password,
                buildHttpClient(verifySsl));
    }

    // Visible for tests.
    F5BigIpAuthClient(ObjectMapper objectMapper,
                      String baseUrl,
                      String username,
                      String password,
                      HttpClient http) {
        this.objectMapper = objectMapper;
        this.baseUrl = baseUrl;
        this.username = username;
        this.password = password;
        this.http = http;
    }

    String baseUrl() {
        return baseUrl;
    }

    /**
     * Best-effort delete of the active iControl token to free a slot in F5's per-user
     * 100-token cap. Called from a finally block in the adapter; never throws.
     */
    void logout() {
        if (token == null || token.isBlank()) return;
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/mgmt/shared/authz/tokens/" + token))
                    .timeout(REQUEST_TIMEOUT)
                    .header("X-F5-Auth-Token", token)
                    .DELETE()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                log.warn("F5 token logout returned HTTP {}: {}", resp.statusCode(), safeBody(resp.body()));
            }
        } catch (Exception e) {
            log.warn("F5 token logout failed: {}", e.getMessage());
        } finally {
            this.token = null;
            this.tokenExpiry = null;
        }
    }

    HttpResponse<String> sendWithAuth(Function<String, HttpRequest> buildRequest) throws Exception {
        String tok = ensureToken();
        HttpResponse<String> resp = http.send(buildRequest.apply(tok), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() == 401) {
            // Refresh token and retry once.
            this.token = null;
            this.tokenExpiry = null;

            tok = ensureToken();
            resp = http.send(buildRequest.apply(tok), HttpResponse.BodyHandlers.ofString());
        }
        return resp;
    }

    private String ensureToken() throws Exception {
        if (token != null && tokenExpiry != null && Instant.now().isBefore(tokenExpiry.minusSeconds(60))) {
            return token;
        }
        loginAndExtendTtl();
        if (token == null || token.isBlank()) {
            throw new PermanentAgentException("DEPLOY_F5_AUTH_FAILED", "F5 auth returned empty token");
        }
        return token;
    }

    private void loginAndExtendTtl() throws Exception {
        ObjectNode login = objectMapper.createObjectNode();
        login.put("username", username);
        login.put("password", password);
        login.put("loginProviderName", "tmos");

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/mgmt/shared/authn/login"))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(login.toString()))
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw wrapF5Error("DEPLOY_F5_AUTH_FAILED", resp);
        }

        JsonNode root = objectMapper.readTree(resp.body());
        String tok = root.path("token").path("token").asString("");
        int timeout = root.path("token").path("timeout").asInt(1200);

        if (tok.isBlank()) {
            throw new PermanentAgentException("DEPLOY_F5_AUTH_FAILED", "F5 login response missing token");
        }

        this.token = tok;
        this.tokenExpiry = Instant.now().plusSeconds(Math.max(60, timeout));

        // Extend TTL to 10 hours (36000s) — best-effort.
        try {
            ObjectNode patch = objectMapper.createObjectNode();
            patch.put("timeout", 36000);

            HttpRequest patchReq = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/mgmt/shared/authz/tokens/" + tok))
                    .timeout(REQUEST_TIMEOUT)
                    .header("X-F5-Auth-Token", tok)
                    .header("Content-Type", "application/json")
                    .method("PATCH", HttpRequest.BodyPublishers.ofString(patch.toString()))
                    .build();

            HttpResponse<String> patchResp = http.send(patchReq, HttpResponse.BodyHandlers.ofString());
            if (patchResp.statusCode() >= 200 && patchResp.statusCode() < 300) {
                this.tokenExpiry = Instant.now().plusSeconds(36000);
            } else {
                log.warn("F5 token TTL extension failed (HTTP {}): {}",
                        patchResp.statusCode(), safeBody(patchResp.body()));
            }
        } catch (Exception e) {
            log.warn("F5 token TTL extension failed: {}", e.getMessage());
        }
    }

    private RuntimeException wrapF5Error(String code, HttpResponse<String> resp) {
        int status = resp.statusCode();
        String body = safeBody(resp.body());
        String msg = "F5 iControl REST error (HTTP " + status + "): " + body;
        if (status >= 500) {
            return new TransientAgentException(code, msg);
        }
        if (status == 401 || status == 403) {
            return new PermanentAgentException(code, "F5 access denied (HTTP " + status + "): " + body);
        }
        return new PermanentAgentException(code, msg);
    }

    private String safeBody(String body) {
        if (body == null) return "";
        String trimmed = body.trim();
        if (trimmed.length() > 3000) {
            return trimmed.substring(0, 3000) + "...";
        }
        return trimmed;
    }

    private static HttpClient buildHttpClient(boolean verifySsl) {
        if (verifySsl) {
            return HttpClient.newBuilder()
                    .connectTimeout(CONNECT_TIMEOUT)
                    .build();
        }

        try {
            TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                @Override public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                @Override public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                @Override public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
            }};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAll, new SecureRandom());

            SSLParameters sslParameters = new SSLParameters();
            // Disable hostname verification when verifySsl=false (lab only).
            sslParameters.setEndpointIdentificationAlgorithm(null);

            return HttpClient.newBuilder()
                    .connectTimeout(CONNECT_TIMEOUT)
                    .sslContext(sslContext)
                    .sslParameters(sslParameters)
                    .build();

        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_F5_SSL_INIT_FAILED",
                    "Failed to initialize trust-all SSL context for F5 BIG-IP: " + e.getMessage(), e);
        }
    }
}
