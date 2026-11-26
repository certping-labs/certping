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
 * Hostinger DNS provider — places ACME DNS-01 challenge TXT records via the Hostinger DNS Zone API.
 * Credentials passed via constructor (from the credential JSON in the secret store).
 *
 * <p>Expected credential JSON in KV: {@code {"apiToken":"..."}} (Bearer token).
 *
 * <p>API shape (developers.hostinger.com):
 * <ul>
 *   <li>Add:    {@code PUT /api/dns/v1/zones/{domain}} with {@code overwrite=false} so existing
 *       records are preserved and the challenge TXT is appended.</li>
 *   <li>Delete: a TXT value is removed alone by rewriting the set without it; otherwise
 *       {@code DELETE /api/dns/v1/zones/{domain}} filtered by record {@code name}+{@code type}.</li>
 * </ul>
 * Record {@code name} is <b>zone-relative</b> (e.g. {@code _acme-challenge}), not an FQDN.
 */
@Slf4j
public class HostingerDnsProvider implements DnsProvider {

    private static final String API_BASE = "https://developers.hostinger.com/api/dns/v1";
    private static final int TTL = 300; // Hostinger minimum TTL

    private final String apiToken;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public HostingerDnsProvider(String apiToken) {
        if (apiToken == null || apiToken.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "Hostinger API token is blank");
        }
        this.apiToken = apiToken;
        this.httpClient = HttpClient.newBuilder().build();
        this.objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    @Override
    public String addRecord(DnsRecordType type, String recordName, String value) {
        try {
            String domain = extractDomain(recordName);
            String host = extractHost(recordName, domain);

            Map<String, Object> zoneEntry = Map.of(
                    "name", host,
                    "type", type.name(),
                    "ttl", TTL,
                    "records", List.of(Map.of("content", value)));
            Map<String, Object> body = Map.of(
                    "overwrite", false,
                    "zone", List.of(zoneEntry));

            String url = API_BASE + "/zones/" + domain;
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + apiToken)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 401 || resp.statusCode() == 403) {
                throw new PermanentAgentException("DNS_AUTH_FAILED",
                        "Hostinger auth failed: HTTP " + resp.statusCode());
            }
            if (isThrottled(resp.statusCode())) {
                throw retryable("hostinger " + type + " create", recordName, resp);
            }
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                throw new TransientAgentException("DNS_PROVIDER_ERROR",
                        "Hostinger " + type + " create failed: HTTP " + resp.statusCode() + " - " + resp.body());
            }

            String recordId = host + ":" + domain + (type == DnsRecordType.TXT ? ":" + value : "");
            log.info("Hostinger {} record added: {} → {}", type, recordName, recordId);
            return recordId;

        } catch (PermanentAgentException | TransientAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("hostinger " + type + " create", recordName, e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Hostinger " + type + " create error: " + e.getMessage(), e);
        }
    }

    /**
     * Hostinger deletes by name and type only, so a {@code host:domain:value} id rewrites the TXT set without that
     * value, and deletes the set only when nothing else is left in it; a {@code host:domain} id deletes the set.
     */
    @Override
    public void deleteRecord(DnsRecordType type, String recordName, String recordId) {
        try {
            String[] parts = recordId.split(":", 3);
            if (parts.length < 2) {
                log.warn("Hostinger invalid recordId format '{}', skipping deletion", recordId);
                return;
            }
            String host = parts[0];
            String domain = parts[1];
            if (parts.length == 3) {
                Optional<JsonNode> set = existingSet(type, host, domain, recordId);
                List<String> remaining = new ArrayList<>();
                set.ifPresent(found -> found.path("records").forEach(r -> remaining.add(r.path("content").asString(""))));
                if (!remaining.removeIf(content -> unquoted(content).equals(parts[2]))) {
                    log.info("Hostinger {} value at {} already gone, skipping deletion", type, recordName);
                    return;
                }
                if (!remaining.isEmpty()) {
                    overwrite(type, host, domain, set.get().path("ttl").asInt(TTL), remaining, recordId);
                    log.info("Hostinger {} value deleted at {}; {} other value(s) kept", type, recordName,
                            remaining.size());
                    return;
                }
            }

            Map<String, Object> body = Map.of(
                    "filters", List.of(Map.of("name", host, "type", type.name())));

            String url = API_BASE + "/zones/" + domain;
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + apiToken)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .method("DELETE", HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 404) {
                log.warn("Hostinger {} record {} already gone", type, recordId);
            } else if (isThrottled(resp.statusCode())) {
                throw retryable("hostinger " + type + " delete", recordId, resp);
            } else if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                log.warn("Hostinger {} delete returned {}: {}", type, resp.statusCode(), resp.body());
            } else {
                log.info("Hostinger {} record deleted: {}", type, recordId);
            }
        } catch (RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("hostinger " + type + " delete", recordId, e);
            }
            log.warn("Hostinger {} delete failed for {}: {} - treating as non-fatal",
                    type, recordId, e.getMessage());
        }
    }

    private Optional<JsonNode> existingSet(DnsRecordType type, String host, String domain, String target)
            throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "/zones/" + domain))
                .header("Authorization", "Bearer " + apiToken)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (isThrottled(resp.statusCode())) {
            throw retryable("hostinger zone lookup", target, resp);
        }
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Hostinger zone lookup failed: HTTP " + resp.statusCode() + " - " + resp.body());
        }
        for (JsonNode set : objectMapper.readTree(resp.body())) {
            if (host.equalsIgnoreCase(set.path("name").asString(""))
                    && type.name().equalsIgnoreCase(set.path("type").asString(""))) {
                return Optional.of(set);
            }
        }
        return Optional.empty();
    }

    private void overwrite(DnsRecordType type, String host, String domain, int ttl, List<String> contents,
                           String target) throws Exception {
        Map<String, Object> body = Map.of(
                "overwrite", true,
                "zone", List.of(Map.of(
                        "name", host,
                        "type", type.name(),
                        "ttl", ttl,
                        "records", contents.stream().map(content -> Map.of("content", content)).toList())));
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(API_BASE + "/zones/" + domain))
                .header("Authorization", "Bearer " + apiToken)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (isThrottled(resp.statusCode())) {
            throw retryable("hostinger " + type + " delete", target, resp);
        }
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Hostinger " + type + " rewrite failed: HTTP " + resp.statusCode() + " - " + resp.body());
        }
    }

    /** Hostinger may return TXT content wrapped in quotes. */
    private static String unquoted(String content) {
        return content.length() >= 2 && content.startsWith("\"") && content.endsWith("\"")
                ? content.substring(1, content.length() - 1)
                : content;
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /** Strips {@code _acme-challenge.} / {@code *.} and returns the registrable (zone) domain. */
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

    /** Returns the zone-relative host portion (everything before the zone domain). */
    private String extractHost(String recordName, String domain) {
        if (recordName.endsWith("." + domain)) {
            return recordName.substring(0, recordName.length() - domain.length() - 1);
        }
        return "_acme-challenge";
    }

    private boolean isThrottled(int statusCode) {
        return statusCode == 429 || statusCode == 503;
    }

    private RetryableAgentException retryable(String operation, String target, HttpResponse<?> resp) {
        Duration retryAfter = parseRetryAfter(resp);
        return new RetryableAgentException("DNS_PROVIDER_THROTTLED",
                operation + " for " + target + " was rate-limited (HTTP "
                        + resp.statusCode() + (retryAfter == null
                                ? ", no Retry-After supplied)"
                                : ", Retry-After=" + retryAfter + ")"),
                retryAfter, null);
    }

    private Duration parseRetryAfter(HttpResponse<?> resp) {
        if (resp.headers() == null) {
            return null;
        }
        return resp.headers()
                .firstValue("Retry-After")
                .flatMap(RateLimitClassifier::parseRetryAfterValueOpt)
                .orElse(null);
    }
}
