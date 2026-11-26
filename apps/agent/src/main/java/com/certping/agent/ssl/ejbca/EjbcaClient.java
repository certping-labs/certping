// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Transport and authentication for one EJBCA connection.
 *
 * <p>Scoped deliberately to {@code v1/certificate/*}. Those endpoints behave identically on
 * Community and Enterprise across every supported release, which removes the entire
 * edition-and-version compatibility problem from this driver. Setup is in the EJBCA section of
 * {@code docs/integrations.md#machine-identity-experimental}.
 *
 * <p>The credential is read once and the client built from it is long-lived. On an auth failure
 * the session is dropped and the secret re-read, so a rotated credential is picked up without a
 * restart.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class EjbcaClient {

    private static final String REST_BASE = "/ejbca/ejbca-rest-api";
    private static final String JSON = "application/json";

    private final AgentProperties properties;
    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;

    /** Credential, its HTTP client and its token provider, swapped as one so they cannot disagree. */
    private volatile Session session;

    private record Session(EjbcaCredentials credentials,
                           HttpClient httpClient,
                           EjbcaOAuthTokenProvider tokenProvider) {
    }

    /**
     * Submits a CSR for signing.
     *
     * @return the {@code pkcs10enroll} response: {@code certificate} (base64 DER),
     *         {@code serial_number}, {@code response_format}, {@code certificate_chain}
     */
    JsonNode pkcs10Enroll(Map<String, Object> body) {
        return sendJson("POST", "/v1/certificate/pkcs10enroll", toJson(body));
    }

    JsonNode revocationStatus(String issuerDn, String serialNumber) {
        return sendJson("GET", "/v1/certificate/" + pathSegment(issuerDn) + "/"
                + pathSegment(serialNumber) + "/revocationstatus", null);
    }

    void revoke(String issuerDn, String serialNumber, String reason) {
        sendJson("PUT", "/v1/certificate/" + pathSegment(issuerDn) + "/"
                + pathSegment(serialNumber) + "/revoke?reason=" + pathSegment(reason), null);
    }

    /**
     * Returns something like {@code "EJBCA 9.3.7 Community (afce321...)"} — version and edition in
     * one string, reported identically on 7.9.0.2, 8.3.2 and 9.3.7. This is exactly why neither is
     * stored in the credential secret.
     *
     * <p>The endpoint needs no <em>authorization</em>, so a 2xx proves the endpoint is reachable
     * and REST is enabled, separating those from "credential rejected". It is not
     * credential-<em>free</em>: the secret still supplies the base URL and TLS material.
     */
    String probeVersion() {
        Session current = session();
        HttpRequest request = HttpRequest.newBuilder(uri(current, "/v1/certificate/status"))
                .header(HttpHeaders.ACCEPT, JSON)
                .timeout(timeout())
                .GET()
                .build();

        HttpResponse<String> response = send(current, request, "EJBCA status probe");
        EjbcaErrorMapper.assertSuccess(response, "EJBCA status probe");

        JsonNode json = parseJson(response.body(), "EJBCA status probe");
        String revision = json.path("revision").asString("");
        return revision.isBlank() ? json.path("version").asString("unknown") : revision;
    }

    /**
     * Non-secret connection facts for operator-facing reporting. Resolved from the credential,
     * so it is only available once a session exists — callers should probe first and fall back
     * to configuration otherwise.
     */
    ConnectionInfo describeConnection() {
        Session current = session;
        if (current == null) {
            return null;
        }
        return new ConnectionInfo(
                current.credentials().baseUrl(), current.credentials().authMethod().name());
    }

    /** Deliberately carries no credential material — this ends up in an outbound message payload. */
    record ConnectionInfo(String baseUrl, String authMethod) {
    }

    /** Drops the cached credential so the next call re-reads it from the secret store. */
    synchronized void invalidate() {
        session = null;
    }

    /**
     * Compare-and-clear: only discards {@code expected}. Without this, N threads failing on the
     * same stale session each null the field, and a late one throws away the good session a
     * peer already installed — turning one credential rotation into N secret reads and N clients.
     */
    private synchronized void invalidate(Session expected) {
        if (session == expected) {
            session = null;
        }
    }

    private JsonNode sendJson(String method, String path, String body) {
        String operation = operationName(method, path);
        HttpResponse<String> response = sendAuthorized(method, path, body);

        // A 401/403 may just mean the credential rotated under us. Drop the session, re-read the
        // secret and try once more before concluding the credential is genuinely wrong.
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            // Cheapest plausible cause first: on the OAuth path the bearer token may simply have
            // gone stale. Refreshing it avoids a secret-store read and a full TLS rebuild on every
            // permanently-failing 403, which a retrying device fleet would otherwise amplify into
            // sustained load against the customer's vault.
            Session current = session;
            if (current != null
                    && current.credentials().authMethod() == EjbcaCredentials.AuthMethod.OAUTH_CLIENT_CREDENTIALS) {
                log.info("EJBCA returned {} — refreshing OAuth token and retrying once",
                        response.statusCode());
                current.tokenProvider().invalidate(current.tokenProvider().peekToken());
            } else {
                log.info("EJBCA returned {} — reloading credential and retrying once",
                        response.statusCode());
                invalidate(current);
            }
            response = sendAuthorized(method, path, body);
        }

        EjbcaErrorMapper.assertSuccess(response, operation);
        return parseJson(response.body(), operation);
    }

    private HttpResponse<String> sendAuthorized(String method, String path, String body) {
        Session current = session();
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri(current, path))
                .header(HttpHeaders.ACCEPT, JSON)
                .timeout(timeout());

        if (body != null) {
            builder.header(HttpHeaders.CONTENT_TYPE, JSON);
        }
        // mTLS presents its credential during the handshake, so there is no header to add.
        if (current.credentials().authMethod() == EjbcaCredentials.AuthMethod.OAUTH_CLIENT_CREDENTIALS) {
            builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + current.tokenProvider().accessToken());
        }

        HttpRequest request = switch (method) {
            case "GET" -> builder.GET().build();
            case "POST" -> builder.POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body)).build();
            case "PUT" -> builder.PUT(HttpRequest.BodyPublishers.ofString(body == null ? "" : body)).build();
            default -> throw new IllegalArgumentException("Unsupported method: " + method);
        };
        return send(current, request, operationName(method, path));
    }

    private static String operationName(String method, String path) {
        return "EJBCA " + method + " " + path;
    }

    private HttpResponse<String> send(Session current, HttpRequest request, String operation) {
        try {
            return current.httpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException("EJBCA_INTERRUPTED", operation + " was interrupted", e);
        } catch (Exception e) {
            if (hasCause(e, SSLException.class)) {
                // Our side rejected the server's certificate. Configuration, not weather.
                throw new PermanentAgentException("EJBCA_TLS_HANDSHAKE_FAILED",
                        operation + " failed the TLS handshake: " + e.getMessage()
                                + ". 'serverCaChainPem' most likely does not match the CA that "
                                + "issued EJBCA's TLS certificate.", e);
            }
            if (isPossibleClientCertRejection(e)) {
                // Under TLS 1.3 the client finishes its handshake before the server validates the
                // client certificate, so EJBCA refusing our cert arrives as a reset on first read
                // rather than an SSLException — and EJBCA logs nothing at all. A reset is still
                // genuinely ambiguous with a network blip, so this stays retryable; the message
                // carries the hint the operator would otherwise spend hours finding.
                throw new TransientAgentException("EJBCA_CONNECTION_RESET",
                        operation + " was reset by the peer: " + e.getMessage()
                                + ". If this persists on the mTLS path, EJBCA's truststore is "
                                + "probably missing the CA that issued our client certificate — "
                                + "that rejection is silent on the EJBCA side.", e);
            }
            throw new TransientAgentException("EJBCA_NETWORK_ERROR",
                    operation + " failed: " + e.getMessage(), e);
        }
    }

    private static boolean hasCause(Throwable throwable, Class<? extends Throwable> type) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (type.isInstance(current)) {
                return true;
            }
            if (current.getCause() == current) {
                break;
            }
        }
        return false;
    }

    /** A peer reset with no TLS exception in the chain — see the caller for why this matters. */
    private static boolean isPossibleClientCertRejection(Throwable throwable) {
        return hasCause(throwable, java.net.SocketException.class)
                || String.valueOf(throwable.getMessage()).contains("header parser received no bytes");
    }

    private Session session() {
        Session current = session;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (session != null) {
                return session;
            }
            AgentProperties.EjbcaProperties config = properties.getEjbca();
            EjbcaCredentials credentials = EjbcaCredentials.parse(
                    resolveCredentialsJson(config), objectMapper, config.getBaseUrl());
            HttpClient httpClient = EjbcaTlsContextFactory.createHttpClient(credentials, timeout());
            // Deliberately NOT httpClient: that one's truststore is pinned to EJBCA's private CA
            // and would reject a publicly trusted IdP. See EjbcaTlsContextFactory.
            EjbcaOAuthTokenProvider tokenProvider = new EjbcaOAuthTokenProvider(credentials,
                    EjbcaTlsContextFactory.createIdpHttpClient(timeout()), objectMapper, timeout());
            session = new Session(credentials, httpClient, tokenProvider);

            log.info("EJBCA session established: baseUrl={}, authMethod={}",
                    credentials.baseUrl(), credentials.authMethod());
            return session;
        }
    }

    private String resolveCredentialsJson(AgentProperties.EjbcaProperties config) {
        if (config.getCredentialsJson() != null && !config.getCredentialsJson().isBlank()) {
            log.debug("EJBCA credential resolved from agent.ejbca.credentials-json (literal)");
            return config.getCredentialsJson();
        }
        if (config.getCredentialPath() != null && !config.getCredentialPath().isBlank()) {
            log.debug("EJBCA credential resolved from agent.ejbca.credential-path via SecretStore");
            return secretStore.read(config.getCredentialPath());
        }
        throw new PermanentAgentException("EJBCA_CONFIG_MISSING",
                "agent.ejbca.credential-path or agent.ejbca.credentials-json is not configured");
    }

    private URI uri(Session current, String path) {
        return URI.create(current.credentials().baseUrl() + REST_BASE + path);
    }

    private static String pathSegment(String value) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("EJBCA_REQUEST_INVALID",
                    "EJBCA certificate issuer and serial number are required");
        }
        return URLEncoder.encode(value.trim(), StandardCharsets.UTF_8).replace("+", "%20");
    }

    private Duration timeout() {
        return Duration.ofSeconds(Math.max(1, properties.getEjbca().getRequestTimeoutSeconds()));
    }

    private JsonNode parseJson(String raw, String operation) {
        try {
            return objectMapper.readTree(raw);
        } catch (Exception e) {
            throw new PermanentAgentException("EJBCA_RESPONSE_INVALID",
                    operation + " returned a body that is not JSON: " + e.getMessage(), e);
        }
    }

    private String toJson(Map<String, Object> body) {
        try {
            return objectMapper.writeValueAsString(new LinkedHashMap<>(body));
        } catch (Exception e) {
            throw new PermanentAgentException("EJBCA_REQUEST_INVALID",
                    "Failed to serialize the EJBCA request payload", e);
        }
    }
}
