// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

@Component
public class IntuneCertificateProfileClient {
    private static final String PROFILE_COLLECTION =
            "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations";
    private static final int MAX_GRAPH_PAGES = 10_000;
    private final RestTemplate rest;

    @Autowired
    public IntuneCertificateProfileClient(RestTemplateBuilder builder) {
        this(builder.connectTimeout(Duration.ofSeconds(5))
                .readTimeout(Duration.ofSeconds(30)).build());
    }

    IntuneCertificateProfileClient(RestTemplate rest) {
        this.rest = rest;
    }

    public void streamCertificateProfiles(
            String token, Consumer<List<Map<String, Object>>> consumer) {
        String next = PROFILE_COLLECTION;
        Set<String> visited = new HashSet<>();
        int page = 0;
        while (next != null) {
            validateUrl(next, visited, page++);
            Map<String, Object> body = exchange(token, HttpMethod.GET, next, null);
            List<Map<String, Object>> profiles = values(body).stream()
                    .filter(IntuneCertificateProfileClient::isCertificateProfile)
                    .toList();
            if (!profiles.isEmpty()) {
                consumer.accept(profiles);
            }
            next = string(body.get("@odata.nextLink"));
        }
    }

    public void streamManagedDeviceCertificateStates(
            String token,
            String providerProfileId,
            String providerProfileType,
            Consumer<List<Map<String, Object>>> consumer) {
        streamManagedDeviceCertificateStates(
                token, providerProfileId, providerProfileType, MAX_GRAPH_PAGES, consumer);
    }

    int streamManagedDeviceCertificateStates(
            String token,
            String providerProfileId,
            String providerProfileType,
            int maxPages,
            Consumer<List<Map<String, Object>>> consumer) {
        if (maxPages < 1 || maxPages > MAX_GRAPH_PAGES) {
            throw new PermanentAgentException("PROFILE_CORRELATION_BUDGET_EXCEEDED",
                    "The managed-certificate report exceeded its Graph query budget");
        }
        String id = requireProviderId(providerProfileId);
        String type = requireScepProfileType(providerProfileType);
        String next = PROFILE_COLLECTION + "/" + id + "/microsoft.graph." + type
                + "/managedDeviceCertificateStates"
                + "?$top=100";
        Set<String> visited = new HashSet<>();
        int page = 0;
        while (next != null) {
            if (page >= maxPages) {
                throw new PermanentAgentException("PROFILE_CORRELATION_BUDGET_EXCEEDED",
                        "The managed-certificate report exceeded its Graph query budget");
            }
            validateUrl(next, visited, page++);
            Map<String, Object> body = exchange(token, HttpMethod.GET, next, null);
            List<Map<String, Object>> states = values(body);
            if (!states.isEmpty()) {
                consumer.accept(states);
            }
            next = string(body.get("@odata.nextLink"));
        }
        return page;
    }

    /**
     * Finds an earlier CertPing create whose Graph response may have been lost.
     * Graph does not provide an idempotency key for this endpoint, so the stable
     * correlation marker embedded in the description is the recovery key.
     */
    public Optional<Map<String, Object>> findByCorrelationMarker(
            String token, String correlationMarker) {
        if (correlationMarker == null || correlationMarker.isBlank()) {
            return Optional.empty();
        }
        String expected = IntuneProfileMarker.requireValid(correlationMarker);
        List<Map<String, Object>> matches = new ArrayList<>(1);
        streamCertificateProfiles(token, page -> page.stream()
                .filter(profile -> expected.equals(
                        IntuneProfileMarker.extract(string(profile.get("description")))))
                .forEach(matches::add));
        if (matches.size() > 1) {
            throw new PermanentAgentException("PROFILE_CORRELATION_CONFLICT",
                    "More than one Intune profile has the same CertPing correlation marker");
        }
        return matches.stream().findFirst();
    }

    public int probeReadPermission(String token) {
        Map<String, Object> response = exchange(
                token, HttpMethod.GET, PROFILE_COLLECTION + "?$top=1", null);
        return values(response).stream()
                .filter(IntuneCertificateProfileClient::isCertificateProfile)
                .toList().size();
    }

    public Map<String, Object> create(
            String token, Map<String, Object> payload) {
        Map<String, Object> created = exchange(
                token, HttpMethod.POST, PROFILE_COLLECTION, payload);
        String id = requireProviderId(created.get("id"));
        return get(token, id);
    }

    public Map<String, Object> update(
            String token, String providerProfileId, Map<String, Object> payload) {
        String id = requireProviderId(providerProfileId);
        exchange(token, HttpMethod.PATCH, PROFILE_COLLECTION + "/" + id, payload);
        return get(token, id);
    }

    public Map<String, Object> get(String token, String providerProfileId) {
        String id = requireProviderId(providerProfileId);
        return exchange(token, HttpMethod.GET, PROFILE_COLLECTION + "/" + id, null);
    }

    public void linkWindowsScepRootCertificate(
            String token, String scepProfileId, String rootProfileId) {
        String scepId = requireProviderId(scepProfileId);
        String rootId = requireProviderId(rootProfileId);
        exchange(token, HttpMethod.PUT, PROFILE_COLLECTION + "/" + scepId
                        + "/microsoft.graph.windows81SCEPCertificateProfile/rootCertificate/$ref",
                Map.of("@odata.id", PROFILE_COLLECTION + "('" + rootId + "')"));
    }

    /** Graph replaces the profile's whole assignment set with these groups. */
    public void assign(String token, String providerProfileId, List<String> groupIds) {
        String id = requireProviderId(providerProfileId);
        List<Map<String, Object>> assignments = groupIds.stream()
                .<Map<String, Object>>map(groupId -> Map.of("target", Map.of(
                        "@odata.type", "#microsoft.graph.groupAssignmentTarget",
                        "groupId", groupId)))
                .toList();
        exchange(token, HttpMethod.POST, PROFILE_COLLECTION + "/" + id + "/assign",
                Map.of("assignments", assignments));
    }

    private Map<String, Object> exchange(
            String token, HttpMethod method, String url, Map<String, Object> payload) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        if (payload != null) {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }
        try {
            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response =
                    (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) rest.exchange(
                            url, method, new HttpEntity<>(payload, headers), Map.class);
            return response.getBody() == null ? Map.of() : response.getBody();
        } catch (HttpClientErrorException exception) {
            int status = exception.getStatusCode().value();
            if (status == HttpStatus.TOO_MANY_REQUESTS.value()
                    || status == HttpStatus.REQUEST_TIMEOUT.value()) {
                throw retryable("PLATFORM_THROTTLED", "Graph throttled the profile request", exception);
            }
            if (status == HttpStatus.UNAUTHORIZED.value()
                    || status == HttpStatus.FORBIDDEN.value()) {
                throw new PermanentAgentException("INTUNE_CONFIGURATION_PERMISSION_DENIED",
                        "Grant DeviceManagementConfiguration.Read.All for discovery or "
                                + "DeviceManagementConfiguration.ReadWrite.All for mutations", exception);
            }
            if (status == HttpStatus.NOT_FOUND.value()) {
                throw new PermanentAgentException("PROFILE_NOT_FOUND",
                        "The native Intune profile no longer exists", exception);
            }
            throw new PermanentAgentException("PLATFORM_REQUEST_FAILED",
                    "Graph rejected the profile request with status " + status, exception);
        } catch (HttpServerErrorException exception) {
            throw retryable("PLATFORM_REQUEST_FAILED", "Graph profile API is unavailable", exception);
        } catch (ResourceAccessException exception) {
            throw new TransientAgentException("PLATFORM_REQUEST_UNAVAILABLE",
                    "Could not reach the Graph profile API", exception);
        }
    }

    private static RuntimeException retryable(
            String code,
            String message,
            org.springframework.web.client.HttpStatusCodeException exception) {
        Duration retryAfter = RateLimitClassifier.parseRetryAfterValueOpt(
                exception.getResponseHeaders() == null ? null
                        : exception.getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER))
                .orElse(null);
        return retryAfter == null
                ? new TransientAgentException(code, message, exception)
                : new RetryableAgentException(code, message, retryAfter, exception);
    }

    private static boolean isCertificateProfile(Map<String, Object> value) {
        String type = string(value.get("@odata.type"));
        if (type == null) {
            return false;
        }
        String normalized = type.toLowerCase(Locale.ROOT);
        return normalized.contains("certificate")
                || normalized.contains("scep")
                || normalized.contains("pkcs");
    }

    private static String requireProviderId(Object value) {
        String id = string(value);
        if (id == null || !id.matches("[A-Za-z0-9-]{1,100}")) {
            throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID",
                    "Intune returned an invalid profile identifier");
        }
        return id;
    }

    private static String requireScepProfileType(String value) {
        String type = string(value);
        if (type != null && type.startsWith("#microsoft.graph.")) {
            type = type.substring("#microsoft.graph.".length());
        }
        if (type == null || !type.matches("[A-Za-z0-9]{1,150}")
                || !type.toLowerCase(Locale.ROOT).contains("scepcertificateprofile")) {
            throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID",
                    "Intune returned an invalid SCEP profile type");
        }
        return type;
    }

    private static void validateUrl(String url, Set<String> visited, int page) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException exception) {
            throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID",
                    "Graph returned an invalid profile pagination URL", exception);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || !"graph.microsoft.com".equalsIgnoreCase(uri.getHost())
                || page >= MAX_GRAPH_PAGES || !visited.add(url)) {
            throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID",
                    "Graph profile pagination did not terminate safely");
        }
    }

    private static List<Map<String, Object>> values(Map<String, Object> body) {
        Object value = body.get("value");
        if (!(value instanceof List<?> list)) {
            throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID",
                    "Graph profile collection response is missing the value array");
        }
        List<Map<String, Object>> result = new ArrayList<>(list.size());
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> raw)) {
                throw new PermanentAgentException("PLATFORM_RESPONSE_INVALID",
                        "Graph returned a non-object profile");
            }
            Map<String, Object> mapped = new HashMap<>();
            raw.forEach((key, nested) -> {
                if (key != null) {
                    mapped.put(key.toString(), nested);
                }
            });
            result.add(mapped);
        }
        return result;
    }

    private static String string(Object value) {
        return value == null || value.toString().isBlank() ? null : value.toString();
    }

}
