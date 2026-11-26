// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * GoDaddy DNS provider.
 * Credentials passed via constructor (from the credential JSON in the secret store).
 *
 * Expected credential JSON in KV: {"apiKey":"...","apiSecret":"..."}
 */
@Slf4j
public class GoDaddyDnsProvider implements DnsProvider {

    private static final String API_BASE = "https://api.godaddy.com/v1";
    private static final int TTL = 600; // 10 minutes

    private final String apiKey;
    private final String apiSecret;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public GoDaddyDnsProvider(String apiKey, String apiSecret) {
        if (apiKey == null || apiKey.isBlank() || apiSecret == null || apiSecret.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "GoDaddy apiKey / apiSecret is blank");
        }
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.httpClient = HttpClient.newBuilder().build();
        this.objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    /**
     * GoDaddy's PUT replaces every record of the type at the name, so a TXT value is written together with the
     * values already there: the apex and its wildcard can be validated at once. Its id names the value, which
     * the delete removes alone.
     */
    @Override
    public String addRecord(DnsRecordType type, String recordName, String value) {
        try {
            String domain = extractDomain(recordName);
            String host = extractHost(recordName, domain);

            List<Map<String, Object>> records = new ArrayList<>();
            if (type == DnsRecordType.TXT) {
                records.addAll(existingRecords(type, host, domain, recordName));
                records.removeIf(record -> value.equals(record.get("data")));
            }
            records.add(record(type, host, value, TTL));
            replaceRecords(type, host, domain, records, type + " create", recordName);

            String recordId = host + ":" + domain + (type == DnsRecordType.TXT ? ":" + value : "");
            log.info("GoDaddy {} record added: {} at {}:{}", type, recordName, host, domain);
            return recordId;

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("godaddy " + type + " create", recordName, e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "GoDaddy " + type + " create error: " + e.getMessage(), e);
        }
    }

    /** A {@code host:domain:value} id removes that TXT value alone; a {@code host:domain} id, every record. */
    @Override
    public void deleteRecord(DnsRecordType type, String recordName, String recordId) {
        try {
            String[] parts = recordId.split(":", 3);
            if (parts.length < 2) {
                log.warn("GoDaddy invalid recordId format '{}', skipping deletion", recordId);
                return;
            }
            String host = parts[0];
            String domain = parts[1];
            if (parts.length == 3) {
                List<Map<String, Object>> remaining = new ArrayList<>(existingRecords(type, host, domain, recordId));
                if (!remaining.removeIf(record -> parts[2].equals(record.get("data")))) {
                    log.info("GoDaddy {} value at {} already gone, skipping deletion", type, recordName);
                    return;
                }
                if (!remaining.isEmpty()) {
                    replaceRecords(type, host, domain, remaining, type + " delete", recordId);
                    log.info("GoDaddy {} value deleted at {}; {} other value(s) kept", type, recordName,
                            remaining.size());
                    return;
                }
            }
            String url = API_BASE + "/domains/" + domain + "/records/" + type.name() + "/" + host;

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", ssoKey())
                    .DELETE()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 429 || resp.statusCode() == 503) {
                throw throttled(type + " delete", recordId, resp);
            }
            if (resp.statusCode() != 200 && resp.statusCode() != 204) {
                log.warn("GoDaddy {} delete returned {}: {}", type, resp.statusCode(), resp.body());
            } else {
                log.info("GoDaddy {} record deleted: {}", type, recordId);
            }
        } catch (RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("godaddy " + type + " delete", recordId, e);
            }
            log.warn("GoDaddy {} delete failed for {}: {}; treating as non-fatal",
                    type, recordId, e.getMessage());
        }
    }

    private List<Map<String, Object>> existingRecords(DnsRecordType type, String host, String domain,
                                                      String target) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "/domains/" + domain + "/records/" + type.name() + "/" + host))
                .header("Authorization", ssoKey())
                .GET()
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        requireOk(resp, type + " lookup", target);
        String body = resp.body();
        if (body == null || body.isBlank()) {
            return List.of();
        }
        List<Map<String, Object>> records = new ArrayList<>();
        for (JsonNode found : objectMapper.readTree(body)) {
            if (found.hasNonNull("data")) {
                records.add(record(type, host, found.get("data").asString(), found.path("ttl").asInt(TTL)));
            }
        }
        return records;
    }

    private void replaceRecords(DnsRecordType type, String host, String domain, List<Map<String, Object>> records,
                                String operation, String target) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "/domains/" + domain + "/records/" + type.name() + "/" + host))
                .header("Authorization", ssoKey())
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(records)))
                .build();
        requireOk(httpClient.send(req, HttpResponse.BodyHandlers.ofString()), operation, target);
    }

    private static Map<String, Object> record(DnsRecordType type, String host, String data, int ttl) {
        return Map.of("data", data, "ttl", ttl, "name", host, "type", type.name());
    }

    private void requireOk(HttpResponse<String> resp, String operation, String target) {
        if (resp.statusCode() == 429 || resp.statusCode() == 503) {
            throw throttled(operation, target, resp);
        }
        if (resp.statusCode() == 401 || resp.statusCode() == 403) {
            throw new PermanentAgentException("DNS_AUTH_FAILED",
                    "GoDaddy auth failed: HTTP " + resp.statusCode());
        }
        if (resp.statusCode() != 200) {
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "GoDaddy " + operation + " failed: HTTP " + resp.statusCode() + ": " + resp.body());
        }
    }

    private RetryableAgentException throttled(String operation, String target, HttpResponse<?> resp) {
        Duration retryAfter = parseRetryAfter(resp);
        return new RetryableAgentException("DNS_PROVIDER_THROTTLED",
                "godaddy " + operation + " for " + target + " was rate-limited (HTTP "
                        + resp.statusCode() + (retryAfter == null
                                ? ", no Retry-After supplied)"
                                : ", Retry-After=" + retryAfter + ")"),
                retryAfter, null);
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

    private String ssoKey() {
        return "sso-key " + apiKey + ":" + apiSecret;
    }

    /** Strips {@code _acme-challenge.} and returns the registrable domain portion. */
    private String extractDomain(String recordName) {
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

    /** Returns the host portion (everything before the domain). */
    private String extractHost(String recordName, String domain) {
        if (recordName.endsWith("." + domain)) {
            return recordName.substring(0, recordName.length() - domain.length() - 1);
        }
        return "_acme-challenge";
    }
}
