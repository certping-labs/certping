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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Cloudflare DNS provider.
 * Key change: credentials passed via constructor (from the secret store), not Spring beans.
 */
@Slf4j
public class CloudflareDnsProvider implements DnsProvider {

    private static final String API_BASE = "https://api.cloudflare.com/client/v4";
    /** Only an active zone answers on Cloudflare's nameservers; a pending or moved one serves nothing. */
    private static final String ACTIVE_ZONE = "active";

    private final String apiToken;
    /** Set when the token cannot read zones (DNS Edit only): every record goes to this zone. */
    private final String zoneId;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public CloudflareDnsProvider(String apiToken) {
        this(apiToken, null);
    }

    public CloudflareDnsProvider(String apiToken, String zoneId) {
        if (apiToken == null || apiToken.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "Cloudflare API token is blank");
        }
        this.apiToken = apiToken;
        this.zoneId = zoneId == null || zoneId.isBlank() ? null : zoneId.trim();
        this.restTemplate = new RestTemplate();
        this.objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    @Override
    public String addRecord(DnsRecordType type, String recordName, String value) {
        String zoneId = null;
        try {
            zoneId = getZoneId(stripChallengePrefix(recordName));
            String url = API_BASE + "/zones/" + zoneId + "/dns_records";

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("type", type.name());
            body.put("name", recordName);
            body.put("content", value);
            body.put("ttl", 60);
            if (type == DnsRecordType.CNAME) {
                body.put("proxied", false);
            }

            ResponseEntity<JsonNode> resp = restTemplate.exchange(
                    url, HttpMethod.POST, new HttpEntity<>(body, authHeaders()), JsonNode.class);
            JsonNode json = resp.getBody();

            if (json == null || !json.path("success").asBoolean()) {
                log.warn("Cloudflare {} create non-success for {}, attempting duplicate lookup", type, recordName);
                return existingOrMarker(type, recordName, value, zoneId);
            }
            String recordId = json.path("result").path("id").asString();
            log.info("Cloudflare {} record added: {} → {}", type, recordName, recordId);
            return recordId;

        } catch (HttpClientErrorException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("cloudflare " + type + " create", recordName, e);
            }
            if (zoneId != null && e.getStatusCode().value() == 400
                    && e.getResponseBodyAsString().contains("An identical record already exists")) {
                log.info("Cloudflare {} already present (idempotent retry) for {} — reusing existing record", type, recordName);
                return existingOrMarker(type, recordName, value, zoneId);
            }
            if (e.getStatusCode().value() == 401 || e.getStatusCode().value() == 403) {
                throw new PermanentAgentException("DNS_AUTH_FAILED",
                        "Cloudflare auth failed: " + e.getMessage(), e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Cloudflare " + type + " create HTTP error: " + e.getMessage(), e);
        } catch (HttpServerErrorException | ResourceAccessException e) {
            throw unavailable(type + " create", recordName, e);
        }
    }

    @Override
    public void deleteRecord(DnsRecordType type, String recordName, String recordId) {
        if (recordId != null && recordId.startsWith("existing-")) {
            log.info("Skipping deletion of Cloudflare marker record: {}", recordId);
            return;
        }
        try {
            String domain = stripChallengePrefix(recordName);
            String zoneId = getZoneId(domain);
            String url = API_BASE + "/zones/" + zoneId + "/dns_records/" + recordId;

            restTemplate.exchange(url, HttpMethod.DELETE, new HttpEntity<>(authHeaders()), JsonNode.class);
            log.info("Cloudflare {} record deleted: {}", type, recordId);

        } catch (HttpClientErrorException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("cloudflare " + type + " delete", recordName, e);
            }
            if (e.getStatusCode().value() == 404) {
                log.warn("Cloudflare {} record {} already gone", type, recordId);
                return;
            }
            log.warn("Cloudflare {} delete failed for {}: {}", type, recordId, e.getMessage());
        } catch (HttpServerErrorException | ResourceAccessException e) {
            log.warn("Cloudflare {} delete failed for {}: {}", type, recordId, e.getMessage());
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /**
     * The id of the closest zone holding {@code domain} that the token can see: the name itself, then each
     * parent in turn, never a top-level domain. Two labels are not always a zone ({@code example.co.uk}).
     */
    private String getZoneId(String domain) {
        if (zoneId != null) {
            return zoneId;
        }
        String name = domain.endsWith(".") ? domain.substring(0, domain.length() - 1) : domain;
        while (name.indexOf('.') > 0) {
            Optional<String> zoneId = zoneIdNamed(name);
            if (zoneId.isPresent()) {
                return zoneId.get();
            }
            name = name.substring(name.indexOf('.') + 1);
        }
        throw new PermanentAgentException("DNS_ZONE_NOT_FOUND",
                "Cloudflare zone not found for domain: " + domain);
    }

    private Optional<String> zoneIdNamed(String zoneName) {
        String url = API_BASE + "/zones?name=" + zoneName;
        try {
            ResponseEntity<JsonNode> resp = restTemplate.exchange(
                    url, HttpMethod.GET, new HttpEntity<>(authHeaders()), JsonNode.class);
            JsonNode json = resp.getBody();
            if (json == null || !json.path("success").asBoolean()) {
                return Optional.empty();
            }
            for (JsonNode zone : json.path("result")) {
                if (ACTIVE_ZONE.equals(zone.path("status").asString())) {
                    return Optional.of(zone.path("id").asString());
                }
            }
            return Optional.empty();
        } catch (HttpClientErrorException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("cloudflare zone lookup", zoneName, e);
            }
            if (e.getStatusCode().value() == 401 || e.getStatusCode().value() == 403) {
                throw new PermanentAgentException("DNS_AUTH_FAILED",
                        "Cloudflare auth failed looking up zone: " + e.getMessage(), e);
            }
            throw new TransientAgentException("DNS_PROVIDER_ERROR",
                    "Cloudflare zone lookup HTTP error: " + e.getMessage(), e);
        }
    }

    /**
     * The id of the record already holding {@code value}, so it is deleted like one the agent created: an
     * earlier attempt published it. The marker (never deleted) only when it cannot be read back.
     */
    private String existingOrMarker(DnsRecordType type, String recordName, String value, String zoneId) {
        String existing = findExistingRecord(type, recordName, value, zoneId);
        return existing != null ? existing : "existing-" + recordName;
    }

    /** Matched on the content too: the apex and wildcard challenges share one name with different values. */
    private String findExistingRecord(DnsRecordType type, String recordName, String value, String zoneId) {
        try {
            String url = API_BASE + "/zones/" + zoneId + "/dns_records?name=" + recordName + "&type=" + type.name();
            ResponseEntity<JsonNode> resp = restTemplate.exchange(
                    url, HttpMethod.GET, new HttpEntity<>(authHeaders()), JsonNode.class);
            JsonNode json = resp.getBody();
            if (json != null && json.path("success").asBoolean()) {
                for (JsonNode recordNode : json.path("result")) {
                    if (value.equals(unquoted(recordNode.path("content").asString()))) {
                        return recordNode.path("id").asString();
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Cloudflare findExistingRecord failed: {}", e.getMessage());
        }
        return null;
    }

    /** Cloudflare may return TXT content in presentation form, wrapped in double quotes. */
    private static String unquoted(String content) {
        return content.length() >= 2 && content.startsWith("\"") && content.endsWith("\"")
                ? content.substring(1, content.length() - 1)
                : content;
    }

    /** A Cloudflare 5xx or an unreachable API: retried, never a failed certificate. */
    private static RuntimeException unavailable(String operation, String recordName, RestClientException e) {
        return RateLimitClassifier.classify(e, "DNS_PROVIDER_THROTTLED")
                .<RuntimeException>map(rl -> rl.toRetryable("cloudflare " + operation, recordName, e))
                .orElseGet(() -> new TransientAgentException("DNS_PROVIDER_ERROR",
                        "Cloudflare " + operation + " failed: " + e.getMessage(), e));
    }

    private HttpHeaders authHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.setBearerAuth(apiToken);
        return h;
    }

    /** Strips {@code _acme-challenge.} prefix and any leading {@code *.} wildcard. */
    private String stripChallengePrefix(String recordName) {
        String domain = recordName;
        if (domain.startsWith("_acme-challenge.")) {
            domain = domain.substring("_acme-challenge.".length());
        }
        if (domain.startsWith("*.")) {
            domain = domain.substring(2);
        }
        return domain;
    }
}
