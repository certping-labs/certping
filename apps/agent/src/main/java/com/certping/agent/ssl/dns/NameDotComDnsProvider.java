// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Name.com DNS provider.
 * Credentials passed via constructor (from the credential JSON in the secret store).
 *
 * Expected credential JSON in KV: {"username":"...","apiToken":"..."}
 */
@Slf4j
public class NameDotComDnsProvider implements DnsProvider {

    private static final String API_BASE = "https://api.name.com/v4";
    private static final int TTL = 300; // 5 minutes minimum

    private final String username;
    private final String apiToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public NameDotComDnsProvider(String username, String apiToken) {
        if (username == null || username.isBlank() || apiToken == null || apiToken.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "Name.com username / apiToken is blank");
        }
        this.username = username;
        this.apiToken = apiToken;
        this.httpClient = HttpClient.newBuilder().build();
        this.objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    @Override
    public String addRecord(DnsRecordType type, String recordName, String value) {
        try {
            String domainName = extractDomainName(recordName);
            String host = hostIn(recordName, domainName);

            Map<String, Object> payload = Map.of(
                    "type", type.name(),
                    "host", host,
                    "answer", value,
                    "ttl", TTL);

            String url = API_BASE + "/domains/" + domainName + "/records";
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", basicAuth())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 429 || resp.statusCode() == 503) {
                Duration retryAfter = parseRetryAfter(resp);
                throw new RetryableAgentException("DNS_PROVIDER_THROTTLED",
                        "name.com " + type + " create for " + recordName + " was rate-limited (HTTP "
                                + resp.statusCode() + (retryAfter == null
                                        ? ", no Retry-After supplied)"
                                        : ", Retry-After=" + retryAfter + ")"),
                        retryAfter, null);
            }
            if (resp.statusCode() == 401 || resp.statusCode() == 403) {
                throw new PermanentAgentException("DNS_AUTH_FAILED",
                        "Name.com auth failed: HTTP " + resp.statusCode());
            }
            if (resp.statusCode() != 200) {
                throw new TransientAgentException("DNS_PROVIDER_ERROR",
                        "Name.com " + type + " create failed: HTTP " + resp.statusCode() + " — " + resp.body());
            }

            Map<String, Object> responseMap = objectMapper.readValue(resp.body(), new TypeReference<>() {});
            String recordId = String.valueOf(responseMap.get("id"));
            log.info("Name.com {} record added: {} → id={}", type, recordName, recordId);
            return recordId;

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("name.com " + type + " create", recordName, e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Name.com " + type + " create error: " + e.getMessage(), e);
        }
    }

    @Override
    public void deleteRecord(DnsRecordType type, String recordName, String recordId) {
        if (recordId == null || recordId.isBlank()) {
            log.warn("Name.com {} delete: no recordId provided for {}", type, recordName);
            return;
        }
        try {
            String domainName = extractDomainName(recordName);
            String url = API_BASE + "/domains/" + domainName + "/records/" + recordId;

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", basicAuth())
                    .DELETE()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 429 || resp.statusCode() == 503) {
                Duration retryAfter = parseRetryAfter(resp);
                throw new RetryableAgentException("DNS_PROVIDER_THROTTLED",
                        "name.com " + type + " delete for " + recordId + " was rate-limited (HTTP "
                                + resp.statusCode() + (retryAfter == null
                                        ? ", no Retry-After supplied)"
                                        : ", Retry-After=" + retryAfter + ")"),
                        retryAfter, null);
            }
            if (resp.statusCode() != 200 && resp.statusCode() != 204) {
                log.warn("Name.com {} delete returned {}: {}", type, resp.statusCode(), resp.body());
            } else {
                log.info("Name.com {} record deleted: {} (id={})", type, recordName, recordId);
            }
        } catch (RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("name.com " + type + " delete", recordId, e);
            }
            log.warn("Name.com {} delete failed for {}: {} — treating as non-fatal",
                    type, recordId, e.getMessage());
        }
    }

    /** Parses a Retry-After header value as integer seconds. Returns null when absent/unparseable. */
    private Duration parseRetryAfter(HttpResponse<?> resp) {
        Optional<String> raw = resp.headers().firstValue("Retry-After");
        if (raw.isEmpty()) {
            return null;
        }
        try {
            return Duration.ofSeconds(Long.parseLong(raw.get().trim()));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private String basicAuth() {
        String credentials = username + ":" + apiToken;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());
    }

    private static String hostIn(String recordName, String domainName) {
        return recordName.endsWith("." + domainName)
                ? recordName.substring(0, recordName.length() - domainName.length() - 1)
                : recordName;
    }

    /**
     * Extracts the registrable domain from a record name like
     * {@code _acme-challenge.subdomain.example.com} → {@code example.com}.
     */
    private String extractDomainName(String recordName) {
        String domain = recordName;
        if (domain.startsWith("_acme-challenge.")) {
            domain = domain.substring("_acme-challenge.".length());
        }
        if (domain.startsWith("*.")) {
            domain = domain.substring(2);
        }
        String[] parts = domain.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return domain;
    }
}
