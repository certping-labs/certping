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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CertPing DNS provider: writes domain-validation records (TXT, CNAME) through the
 * CertPing DNS token API, authenticated with the organization's {@code cpk_live_} key: dns:edit to write, and
 * dns:read to find a record it already created when the response to that create was lost.
 *
 * <p>Credential JSON in KV: {@code {"apiKey":"cpk_live_…"}}. The base URL comes from the
 * deployment, never from the credential.</p>
 *
 * <p>The API takes a host relative to its zone, so the zone is found by posting to each parent
 * of the record name, most specific first, until one is not a 404. The returned record id is
 * {@code <zone>/<id>}, which is all a delete needs.</p>
 */
@Slf4j
public class CertPingDnsProvider implements DnsProvider {

    public static final String DEFAULT_API_BASE = "https://dns-api.certping.com/api/v1/domains/token-api";

    private static final int TTL = 60;
    private static final int MIN_ZONE_LABELS = 2;
    private static final String EXISTING_MARKER = "existing-";
    private static final int MAX_PAGE_SIZE = 100;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final String apiKey;
    private final String apiUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    /** Record name's domain → the zone that accepted a record for it. */
    private final Map<String, String> zoneCache = new ConcurrentHashMap<>();

    public CertPingDnsProvider(String apiKey, String apiUrl) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID", "CertPing DNS apiKey is blank");
        }
        String base = (apiUrl == null || apiUrl.isBlank()) ? DEFAULT_API_BASE : apiUrl.trim();
        this.apiKey = apiKey;
        this.apiUrl = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        this.httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    }

    @Override
    public String addRecord(DnsRecordType type, String recordName, String value) {
        String name = normalize(recordName);
        String cached = zoneCache.get(parentOf(name));
        List<String> zones = cached != null ? List.of(cached) : candidateZones(name);

        for (String zone : zones) {
            HttpResponse<String> resp = send("POST", recordsUri(zone), body(type, hostIn(name, zone), value), recordName);
            int status = resp.statusCode();
            if (status == 404) {
                continue;
            }
            if (status == 409) {
                return existingOrRefused(type, resp, zone, name, value, recordName);
            }
            rejectFailure(resp, type + " create", recordName);
            zoneCache.put(parentOf(name), zone);
            String id = idOf(resp.body());
            log.info("CertPing DNS {} record added: {} in zone {} (id {})", type, name, zone, id);
            return zone + "/" + id;
        }
        throw new PermanentAgentException("DNS_ZONE_NOT_FOUND",
                "No CertPing DNS zone of this organization holds " + recordName);
    }

    @Override
    public void deleteRecord(DnsRecordType type, String recordName, String recordId) {
        if (recordId == null || recordId.startsWith(EXISTING_MARKER)) {
            return;
        }
        int slash = recordId.lastIndexOf('/');
        if (slash <= 0 || slash == recordId.length() - 1) {
            log.warn("CertPing DNS record id {} for {} is not <zone>/<id>; skipping cleanup", recordId, recordName);
            return;
        }
        String zone = recordId.substring(0, slash);
        String id = recordId.substring(slash + 1);
        try {
            HttpResponse<String> resp = send("DELETE", URI.create(recordsUri(zone) + "/" + id), null, recordName);
            if (resp.statusCode() == 404) {
                log.info("CertPing DNS {} record {} already gone", type, recordId);
                return;
            }
            rejectFailure(resp, type + " delete", recordName);
            log.info("CertPing DNS {} record deleted: {}", type, recordId);
        } catch (RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            log.warn("CertPing DNS {} delete failed for {}: {}; treating as non-fatal", type, recordId, e.getMessage());
        }
    }

    /**
     * The token API answers 409 for three reasons. Only "already exists" is a record to leave in
     * place; a zone not open for writes and a CNAME sharing the name with other records would fail validation.
     */
    private String existingOrRefused(DnsRecordType type, HttpResponse<String> resp, String zone, String name,
                                     String value, String recordName) {
        String message = messageOf(resp.body());
        if (message.contains("already exists")) {
            return existingRecordId(type, zone, name, value)
                    .map(id -> zone + "/" + id)
                    .orElseGet(() -> {
                        log.warn("CertPing DNS {} {} with this value already exists and cannot be read back;"
                                + " leaving it in place", type, name);
                        return EXISTING_MARKER + name;
                    });
        }
        String detail = "CertPing DNS " + type + " create for " + recordName + " failed: HTTP 409 " + message;
        if (message.contains("serviceable state")) {
            throw new PermanentAgentException("DNS_ZONE_NOT_SERVICEABLE", detail);
        }
        throw new PermanentAgentException("DNS_PROVIDER_ERROR", detail);
    }

    /**
     * The id of the record already holding {@code value} at {@code name}, so the caller deletes it like one it
     * created: it is the agent's own, left by an attempt whose response was lost. Empty when the key may not
     * read records (no dns:read) or the lookup fails.
     */
    private Optional<String> existingRecordId(DnsRecordType type, String zone, String name, String value) {
        URI uri = URI.create(recordsUri(zone) + "?type=" + type.name() + "&name="
                + URLEncoder.encode(hostIn(name, zone), StandardCharsets.UTF_8) + "&size=" + MAX_PAGE_SIZE);
        try {
            HttpResponse<String> resp = send("GET", uri, null, name);
            if (resp.statusCode() != 200) {
                return Optional.empty();
            }
            for (JsonNode item : objectMapper.readTree(resp.body()).path("items")) {
                if (sameValue(type, item.path("value").asString(""), value)) {
                    return Optional.of(item.path("id").asString()).filter(id -> !id.isBlank());
                }
            }
        } catch (Exception e) {
            log.warn("CertPing DNS lookup of the existing {} at {} failed: {}", type, name, e.getMessage());
        }
        return Optional.empty();
    }

    private static boolean sameValue(DnsRecordType type, String stored, String value) {
        return type == DnsRecordType.CNAME
                ? withoutTrailingDot(stored).equalsIgnoreCase(withoutTrailingDot(value))
                : stored.equals(value);
    }

    private static String withoutTrailingDot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }

    private void rejectFailure(HttpResponse<String> resp, String operation, String recordName) {
        int status = resp.statusCode();
        if (status == 201 || status == 202 || status == 204) {
            return;
        }
        String message = "CertPing DNS " + operation + " for " + recordName + " failed: HTTP " + status
                + " " + messageOf(resp.body());
        if (status == 429 || status == 503) {
            throw new RetryableAgentException("DNS_PROVIDER_THROTTLED", message, retryAfter(resp), null);
        }
        if (status == 401 || status == 403) {
            throw new PermanentAgentException("DNS_AUTH_FAILED", message);
        }
        if (status >= 400 && status < 500) {
            throw new PermanentAgentException("DNS_PROVIDER_ERROR", message);
        }
        throw new TransientAgentException("DNS_PROVIDER_ERROR", message);
    }

    private HttpResponse<String> send(String method, URI uri, String body, String recordName) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(uri)
                .header("Authorization", "Bearer " + apiKey)
                .timeout(REQUEST_TIMEOUT);
        if (body == null) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            builder.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body));
        }
        try {
            return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "CertPing DNS " + method + " interrupted for " + recordName, e);
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("certping dns " + method, recordName, e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "CertPing DNS " + method + " error for " + recordName + ": " + e.getMessage(), e);
        }
    }

    private URI recordsUri(String zone) {
        return URI.create(apiUrl + "/dns/zones/" + zone + "/records");
    }

    private String body(DnsRecordType type, String host, String value) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("recordType", type.name());
        rec.put("host", host);
        rec.put("value", value);
        rec.put("ttl", TTL);
        try {
            return objectMapper.writeValueAsString(rec);
        } catch (Exception e) {
            throw new PermanentAgentException("DNS_PROVIDER_ERROR",
                    "Failed to serialize CertPing DNS record: " + e.getMessage(), e);
        }
    }

    private String idOf(String body) {
        try {
            String id = objectMapper.readTree(body).path("id").asString("");
            if (!id.isBlank()) {
                return id;
            }
        } catch (Exception ignored) {
            // falls through to the error below
        }
        throw new TransientAgentException("DNS_PROVIDER_ERROR", "CertPing DNS created a record but returned no id: " + body);
    }

    private String messageOf(String body) {
        try {
            String message = objectMapper.readTree(body).path("message").asString("");
            return message.isBlank() ? body : message;
        } catch (Exception e) {
            return body;
        }
    }

    private static String normalize(String recordName) {
        String name = recordName.trim().toLowerCase();
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }

    private static String parentOf(String name) {
        int dot = name.indexOf('.');
        return dot < 0 ? name : name.substring(dot + 1);
    }

    /**
     * Zones that may hold {@code name}, most specific first, down to {@link #MIN_ZONE_LABELS} labels. The name
     * itself is a candidate (a record at the zone apex, as GlobalSign's domain claim needs) unless its first
     * label is an underscore label such as {@code _acme-challenge}.
     */
    static List<String> candidateZones(String name) {
        String[] labels = normalize(name).split("\\.");
        List<String> zones = new ArrayList<>();
        for (int i = labels[0].startsWith("_") ? 1 : 0; i <= labels.length - MIN_ZONE_LABELS; i++) {
            zones.add(String.join(".", List.of(labels).subList(i, labels.length)));
        }
        return zones;
    }

    private static String hostIn(String name, String zone) {
        return name.equals(zone) ? "@" : name.substring(0, name.length() - zone.length() - 1);
    }

    private static Duration retryAfter(HttpResponse<?> resp) {
        try {
            return resp.headers().firstValue("Retry-After")
                    .map(v -> Duration.ofSeconds(Long.parseLong(v.trim())))
                    .orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
