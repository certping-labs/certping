// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;

import javax.net.ssl.SSLHandshakeException;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

/**
 * Client-credentials tokens for the OAuth auth method, cached until shortly before expiry.
 *
 * <p>Entra ID, Keycloak and PingID differ only in the token URL and whether {@code scope} or
 * {@code audience} is required, so no per-IdP code is needed.
 */
final class EjbcaOAuthTokenProvider {

    /** Refresh this early so a token cannot expire in flight. */
    private static final long EXPIRY_SKEW_SECONDS = 30;
    private static final long MIN_TOKEN_LIFETIME_SECONDS = 60;
    private static final long DEFAULT_TOKEN_LIFETIME_SECONDS = 3600;

    private final EjbcaCredentials credentials;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration timeout;

    /** One immutable pair swapped atomically, so a reader can never see a stale token
     *  alongside a freshly extended expiry. */
    private volatile CachedToken cached = CachedToken.EMPTY;

    private record CachedToken(String value, Instant expiresAt) {
        static final CachedToken EMPTY = new CachedToken(null, Instant.EPOCH);

        boolean isCurrent() {
            return value != null && Instant.now().isBefore(expiresAt);
        }
    }

    EjbcaOAuthTokenProvider(EjbcaCredentials credentials, HttpClient httpClient,
                            ObjectMapper objectMapper, Duration timeout) {
        this.credentials = credentials;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.timeout = timeout;
    }

    String accessToken() {
        CachedToken current = cached;
        if (current.isCurrent()) {
            return current.value();
        }
        synchronized (this) {
            if (cached.isCurrent()) {
                return cached.value();
            }
            JsonNode response = requestToken();
            String token = response.path("access_token").asString(null);
            if (token == null || token.isBlank()) {
                throw new PermanentAgentException("EJBCA_OAUTH_TOKEN_FAILED",
                        "IdP token response contained no access_token");
            }
            long lifetime = response.path("expires_in").asLong(DEFAULT_TOKEN_LIFETIME_SECONDS);
            cached = new CachedToken(token, Instant.now().plusSeconds(
                    Math.max(MIN_TOKEN_LIFETIME_SECONDS, lifetime - EXPIRY_SKEW_SECONDS)));
            return token;
        }
    }

    /** The currently cached token, or null. Used to make invalidation compare-and-swap. */
    String peekToken() {
        return cached.value();
    }

    /**
     * Forces the next {@link #accessToken()} to fetch a fresh token, but only discards the token
     * the caller actually saw fail. Clearing unconditionally would let a thread holding a stale
     * token throw away a good one a peer just fetched, queueing everyone behind another IdP
     * round trip — the same reasoning as {@code EjbcaClient.invalidate(Session)}.
     */
    synchronized void invalidate(String staleToken) {
        if (staleToken == null || staleToken.equals(cached.value())) {
            cached = CachedToken.EMPTY;
        }
    }

    private JsonNode requestToken() {
        URI tokenUri;
        try {
            tokenUri = URI.create(credentials.tokenUrl());
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("EJBCA_CREDENTIAL_INVALID",
                    "EJBCA credential 'tokenUrl' is not a valid URI: " + e.getMessage(), e);
        }

        HttpRequest request = HttpRequest.newBuilder(tokenUri)
                .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(HttpHeaders.ACCEPT, "application/json")
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(formBody()))
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException("EJBCA_INTERRUPTED",
                    "Interrupted requesting an OAuth token for EJBCA", e);
        } catch (SSLHandshakeException e) {
            // Configuration, not weather: retrying through the backoff curve would waste the
            // whole retry budget and report a network fault the operator cannot act on.
            throw new PermanentAgentException("EJBCA_OAUTH_TLS_FAILED",
                    "TLS handshake with the IdP at " + tokenUri.getHost() + " failed: "
                            + e.getMessage() + ". Check tokenUrl and the IdP's certificate chain.", e);
        } catch (Exception e) {
            throw new TransientAgentException("EJBCA_NETWORK_ERROR",
                    "EJBCA OAuth token request failed: " + e.getMessage(), e);
        }

        int status = response.statusCode();
        if (status == 429 || status == 408 || status >= 500) {
            // Entra rate-limits the client-credentials grant and has incidents. Dead-lettering
            // here loses a device's certificate that would succeed seconds later — the same
            // reasoning EjbcaErrorMapper applies to EJBCA's own 429/503/408.
            Duration retryAfter = response.headers().firstValue("retry-after")
                    .flatMap(RateLimitClassifier::parseRetryAfterValueOpt)
                    .orElse(null);
            throw new RetryableAgentException("CA_PROVIDER_THROTTLED",
                    "IdP token endpoint returned HTTP " + status
                            + (retryAfter == null ? " (no Retry-After supplied)"
                                                  : " (Retry-After=" + retryAfter + ")"),
                    retryAfter);
        }
        if (status < 200 || status >= 300) {
            // 400/401/invalid_client: the credential itself is wrong, and retrying cannot help.
            throw new PermanentAgentException("EJBCA_OAUTH_TOKEN_FAILED",
                    "IdP rejected the client-credentials grant (" + status + ")");
        }
        try {
            return objectMapper.readTree(response.body());
        } catch (Exception e) {
            throw new PermanentAgentException("EJBCA_RESPONSE_INVALID",
                    "IdP token response was not JSON: " + e.getMessage(), e);
        }
    }

    private String formBody() {
        StringBuilder form = new StringBuilder("grant_type=client_credentials")
                .append("&client_id=").append(encode(credentials.clientId()))
                .append("&client_secret=").append(encode(credentials.clientSecret()));
        if (credentials.scope() != null) {
            form.append("&scope=").append(encode(credentials.scope()));
        }
        if (credentials.audience() != null) {
            form.append("&audience=").append(encode(credentials.audience()));
        }
        return form.toString();
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
