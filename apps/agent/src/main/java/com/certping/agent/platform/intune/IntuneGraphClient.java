// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Thin Microsoft Graph client for device identity sync.
 *
 * <p>Read-only for device inventory ({@code DeviceManagementManagedDevices.Read.All} +
 * {@code Device.Read.All}), plus one best-effort device action, {@link #syncDevice}, which forces a
 * check-in to accelerate SCEP renewal and needs {@code DeviceManagementManagedDevices.PrivilegedOperations.All}.
 * Wipe and retire remain a deliberate non-goal.
 *
 * <p>Runs in the customer's environment. The client secret is resolved by the caller through
 * the agent's selected secret-store backend and never leaves this process.
 */
@Slf4j
@Component
public class IntuneGraphClient {

    private static final String GRAPH_BASE = "https://graph.microsoft.com/v1.0";
    private static final String TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/%s/oauth2/v2.0/token";
    private static final String GRAPH_SCOPE = "https://graph.microsoft.com/.default";
    private static final int GRAPH_BATCH_LIMIT = 20;
    private static final int MAX_GRAPH_PAGES = 100_000;

    /**
     * Fields safe to request from the {@code managedDevices} collection.
     *
     * <p>Deliberately excludes {@code udid}, {@code ethernetMacAddress} and {@code iccid}:
     * verified against a live tenant, the collection endpoint returns null for those
     * <em>even when they are named explicitly in {@code $select}</em>. They are only
     * available from a single-device GET and are fetched lazily, not during sync.
     *
     * <p>Also excludes {@code activationLockBypassCode}, which is a working Apple
     * Activation Lock bypass code. It must never be requested, stored or logged.
     */
    private static final String MANAGED_DEVICE_SELECT = String.join(",",
            "id", "deviceName", "managedDeviceName", "azureADDeviceId", "serialNumber",
            "imei", "meid", "wiFiMacAddress", "operatingSystem", "osVersion",
            "manufacturer", "model",
            "deviceCategoryDisplayName", "enrollmentProfileName", "managedDeviceOwnerType",
            "complianceState", "deviceRegistrationState", "managementAgent", "managementState",
            "isEncrypted", "isSupervised", "jailBroken", "enrolledDateTime", "lastSyncDateTime",
            "easActivated", "azureADRegistered", "exchangeAccessState",
            "exchangeAccessStateReason", "partnerReportedThreatState",
            "requireUserEnrollmentApproval", "managementCertificateExpirationDate",
            "complianceGracePeriodExpirationDateTime", "androidSecurityPatchLevel");

    private static final String ENTRA_DEVICE_SELECT =
            "id,deviceId,displayName,managementType,deviceOwnership,enrollmentType,operatingSystem";

    private final RestTemplate rest;

    @Autowired
    public IntuneGraphClient(RestTemplateBuilder builder) {
        this(builder
                .connectTimeout(Duration.ofSeconds(5))
                .readTimeout(Duration.ofSeconds(30))
                .build());
    }

    IntuneGraphClient(RestTemplate rest) {
        this.rest = rest;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Auth
    // ═══════════════════════════════════════════════════════════════════════

    /** Client-credentials token. Valid ~60 minutes; callers hold it for one sync run. */
    public String acquireToken(String tenantId, String clientId, String clientSecret) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("scope", GRAPH_SCOPE);
        form.add("grant_type", "client_credentials");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        try {
            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>)
                    rest.exchange(String.format(TOKEN_URL_TEMPLATE, tenantId), HttpMethod.POST,
                            new HttpEntity<>(form, headers), Map.class);

            Object token = response.getBody() == null ? null : response.getBody().get("access_token");
            if (token == null) {
                throw new PermanentAgentException("PLATFORM_AUTH_FAILED", "No access_token in Entra response");
            }
            return token.toString();
        } catch (HttpClientErrorException e) {
            if (isRetryableStatus(e.getStatusCode().value())) {
                throw retryable("PLATFORM_AUTH_FAILED", "Entra token endpoint throttled", e);
            }
            throw new PermanentAgentException("PLATFORM_AUTH_FAILED",
                    "Entra token request rejected: " + e.getStatusCode(), e);
        } catch (HttpServerErrorException e) {
            throw retryable("PLATFORM_AUTH_FAILED", "Entra token endpoint unavailable", e);
        } catch (ResourceAccessException e) {
            throw new TransientAgentException(
                    "PLATFORM_AUTH_UNAVAILABLE", "Could not reach the Entra token endpoint", e);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Devices
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Streams the fleet, one page at a time.
     *
     * <p>Always the complete fleet, never filtered. Filtering on {@code complianceState} would
     * be a data-corruption bug — a device that becomes non-compliant would drop out of the
     * results and be orphaned — and filtering on a {@code lastSyncDateTime} watermark would
     * return only changed devices, which makes a deleted device indistinguishable from an
     * unchanged one and so makes orphan detection impossible.
     */
    public void streamManagedDevices(String token, Consumer<List<Map<String, Object>>> pageConsumer) {
        String next = GRAPH_BASE + "/deviceManagement/managedDevices?$select=" + MANAGED_DEVICE_SELECT;
        int page = 0;
        int devices = 0;
        Set<String> visited = new HashSet<>();
        while (next != null) {
            validateNextLink(next, visited, page);
            Map<String, Object> body = get(token, next);
            List<Map<String, Object>> pageValues = values(body);
            pageConsumer.accept(pageValues);
            devices += pageValues.size();
            // Per page, so DEBUG: a large tenant is dozens of pages per sync. Without it a crawl
            // stuck on Graph latency is indistinguishable from a dead agent.
            log.debug("Graph managedDevices page fetched: page={} devices={}", page, pageValues.size());
            next = stringValue(body.get("@odata.nextLink"));
            page++;
        }
        log.info("Intune managedDevices crawl finished: pages={} devices={}", page, devices);
    }

    /**
     * Cheapest call that proves the app can actually read the Intune fleet.
     *
     * <p>Deliberately {@code managedDevices} and not {@code /devices}: the sync stands or falls
     * on {@code DeviceManagementManagedDevices.Read.All}, and a tenant granted only
     * {@code Device.Read.All} would pass a probe against {@code /devices} and then fail every
     * sync with a permission error. A connection test has to fail for the same reasons a sync
     * would.
     *
     * @return devices visible to the app, capped at one — this is a permission check, not a count
     */
    public int probeManagedDevices(String token) {
        Map<String, Object> body = get(token,
                GRAPH_BASE + "/deviceManagement/managedDevices?$select=id&$top=1");
        return values(body).size();
    }

    /** Verifies the second permission required by sync without loading the directory. */
    public void probeEntraDevices(String token) {
        get(token, GRAPH_BASE + "/devices?$select=id&$top=1");
    }

    /**
     * Enriches only the managed devices in one Intune page. Microsoft Graph accepts at most
     * 20 requests in one JSON batch, so the retained map is bounded by the current page rather
     * than the tenant's complete Entra directory.
     */
    public Map<String, Map<String, Object>> fetchEntraDevicesForManagedPage(
            String token, List<Map<String, Object>> managedDevices) {
        Set<String> deviceIds = new LinkedHashSet<>();
        for (Map<String, Object> managedDevice : managedDevices) {
            String deviceId = stringValue(managedDevice.get("azureADDeviceId"));
            if (isDeviceId(deviceId)) {
                deviceIds.add(deviceId);
            }
        }
        Map<String, Map<String, Object>> byDeviceId = new HashMap<>();
        List<String> ids = List.copyOf(deviceIds);
        for (int start = 0; start < ids.size(); start += GRAPH_BATCH_LIMIT) {
            int end = Math.min(start + GRAPH_BATCH_LIMIT, ids.size());
            fetchEntraBatch(token, ids.subList(start, end), byDeviceId);
        }
        return byDeviceId;
    }

    // ═══════════════════════════════════════════════════════════════════════

    private Map<String, Object> get(String token, String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));

        try {
            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>)
                    rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), Map.class);
            return response.getBody() == null ? Map.of() : response.getBody();
        } catch (HttpClientErrorException e) {
            if (isRetryableStatus(e.getStatusCode().value())) {
                // The operator's early warning for tenant-wide 429 trouble, and the reason a sync
                // comes back partial. Per throttle event, not per device.
                log.warn("Graph throttled the request: retryAfter={}", e.getResponseHeaders() == null
                        ? null : e.getResponseHeaders().getFirst("Retry-After"));
                throw retryable("PLATFORM_THROTTLED", "Graph throttled the request", e);
            }
            if (e.getStatusCode() == HttpStatus.FORBIDDEN || e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new PermanentAgentException("PLATFORM_PERMISSION_DENIED",
                        "Graph rejected the request; check admin consent for the Entra app", e);
            }
            throw new PermanentAgentException("PLATFORM_REQUEST_FAILED",
                    "Graph request failed: " + e.getStatusCode(), e);
        } catch (HttpServerErrorException e) {
            throw retryable("PLATFORM_REQUEST_FAILED", "Graph unavailable", e);
        } catch (ResourceAccessException e) {
            throw new TransientAgentException(
                    "PLATFORM_REQUEST_UNAVAILABLE", "Could not reach Microsoft Graph", e);
        }
    }

    private void fetchEntraBatch(String token,
                                 List<String> deviceIds,
                                 Map<String, Map<String, Object>> target) {
        List<Map<String, Object>> requests = new ArrayList<>(deviceIds.size());
        for (int index = 0; index < deviceIds.size(); index++) {
            String deviceId = deviceIds.get(index);
            requests.add(Map.of(
                    "id", String.valueOf(index),
                    "method", "GET",
                    "url", "/devices(deviceId='" + deviceId + "')?$select=" + ENTRA_DEVICE_SELECT));
        }

        Map<String, Object> body = post(token, GRAPH_BASE + "/$batch", Map.of("requests", requests));
        List<Map<String, Object>> responses = maps(body.get("responses"));
        if (responses.size() != deviceIds.size()) {
            throw new PermanentAgentException(
                    "PLATFORM_RESPONSE_INVALID", "Graph batch response count does not match the request count");
        }
        Set<Integer> seenIndexes = new HashSet<>();
        for (Map<String, Object> response : responses) {
            int index = integerValue(response.get("id"), -1);
            int status = integerValue(response.get("status"), 500);
            if (index < 0 || index >= deviceIds.size() || !seenIndexes.add(index)) {
                throw new PermanentAgentException(
                        "PLATFORM_RESPONSE_INVALID", "Graph batch response has an invalid request id");
            }
            if (status == HttpStatus.NOT_FOUND.value()) {
                continue;
            }
            if (isRetryableStatus(status) || status >= 500) {
                Duration retryAfter = retryAfterFromBatch(response);
                if (retryAfter != null) {
                    throw new RetryableAgentException(
                            "PLATFORM_THROTTLED", "Graph batch request was throttled", retryAfter);
                }
                throw new TransientAgentException(
                        "PLATFORM_REQUEST_FAILED", "Graph batch request failed with status " + status);
            }
            if (status == HttpStatus.FORBIDDEN.value() || status == HttpStatus.UNAUTHORIZED.value()) {
                throw new PermanentAgentException(
                        "PLATFORM_PERMISSION_DENIED", "Graph rejected Entra device enrichment");
            }
            if (status < 200 || status >= 300) {
                throw new PermanentAgentException(
                        "PLATFORM_REQUEST_FAILED", "Graph batch request failed with status " + status);
            }
            Object responseBody = response.get("body");
            if (responseBody instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> device = (Map<String, Object>) map;
                target.put(deviceIds.get(index), device);
            }
        }
    }

    /**
     * Forces one managed device to check in with Intune (best-effort). Returns on {@code 204}; on
     * failure throws a classified exception so the caller can record an outcome without retrying the
     * inbound message. {@code 404} = device unknown, {@code 403/401} = missing the PrivilegedOperations
     * role, {@code 429/5xx}/transport = transient.
     */
    public void syncDevice(String token, String managedDeviceId) {
        String canonicalDeviceId;
        try {
            canonicalDeviceId = UUID.fromString(managedDeviceId == null
                    ? "" : managedDeviceId.trim()).toString();
        } catch (IllegalArgumentException exception) {
            throw new PermanentAgentException(
                    "INVALID_MANAGED_DEVICE_ID", "managedDeviceId must be a UUID", exception);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        String url = GRAPH_BASE + "/deviceManagement/managedDevices/" + canonicalDeviceId + "/syncDevice";
        try {
            rest.exchange(url, HttpMethod.POST, new HttpEntity<>(headers), Void.class);
        } catch (HttpClientErrorException e) {
            int status = e.getStatusCode().value();
            if (status == HttpStatus.NOT_FOUND.value()) {
                throw new PermanentAgentException("DEVICE_NOT_FOUND",
                        "Intune has no managed device for the requested id", e);
            }
            if (status == HttpStatus.FORBIDDEN.value() || status == HttpStatus.UNAUTHORIZED.value()) {
                throw new PermanentAgentException("PERMISSION_DENIED",
                        "syncDevice rejected; grant DeviceManagementManagedDevices.PrivilegedOperations.All", e);
            }
            if (isRetryableStatus(e.getStatusCode().value())) {
                throw retryable("PLATFORM_THROTTLED", "syncDevice throttled", e);
            }
            throw new PermanentAgentException("SYNC_DEVICE_REJECTED",
                    "syncDevice failed with status " + status, e);
        } catch (HttpServerErrorException e) {
            throw retryable("PLATFORM_REQUEST_FAILED", "Intune unavailable for syncDevice", e);
        } catch (ResourceAccessException e) {
            throw new TransientAgentException(
                    "PLATFORM_REQUEST_UNAVAILABLE", "Could not reach Intune for syncDevice", e);
        }
    }

    private Map<String, Object> post(String token, String url, Map<String, Object> payload) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        try {
            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>)
                    rest.exchange(url, HttpMethod.POST, new HttpEntity<>(payload, headers), Map.class);
            return response.getBody() == null ? Map.of() : response.getBody();
        } catch (HttpClientErrorException e) {
            if (isRetryableStatus(e.getStatusCode().value())) {
                throw retryable("PLATFORM_THROTTLED", "Graph batch endpoint throttled the request", e);
            }
            throw new PermanentAgentException(
                    "PLATFORM_REQUEST_FAILED", "Graph batch endpoint rejected the request", e);
        } catch (HttpServerErrorException e) {
            throw retryable("PLATFORM_REQUEST_FAILED", "Graph batch endpoint unavailable", e);
        } catch (ResourceAccessException e) {
            throw new TransientAgentException(
                    "PLATFORM_REQUEST_UNAVAILABLE", "Could not reach the Graph batch endpoint", e);
        }
    }

    private static RuntimeException retryable(String code, String message,
                                              org.springframework.web.client.HttpStatusCodeException exception) {
        Duration retryAfter = RateLimitClassifier
                .parseRetryAfterValueOpt(exception.getResponseHeaders() == null
                        ? null : exception.getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER))
                .orElse(null);
        return retryAfter == null
                ? new TransientAgentException(code, message, exception)
                : new RetryableAgentException(code, message, retryAfter, exception);
    }

    private static Duration retryAfterFromBatch(Map<String, Object> response) {
        Object rawHeaders = response.get("headers");
        if (!(rawHeaders instanceof Map<?, ?> headers)) {
            return null;
        }
        for (Map.Entry<?, ?> entry : headers.entrySet()) {
            if (entry.getKey() != null && "retry-after".equalsIgnoreCase(entry.getKey().toString())) {
                return RateLimitClassifier.parseRetryAfterValueOpt(String.valueOf(entry.getValue())).orElse(null);
            }
        }
        return null;
    }

    private static void validateNextLink(String next, Set<String> visited, int page) {
        URI uri;
        try {
            uri = URI.create(next);
        } catch (IllegalArgumentException exception) {
            throw new PermanentAgentException(
                    "PLATFORM_RESPONSE_INVALID", "Graph returned an invalid pagination URL", exception);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || !"graph.microsoft.com".equalsIgnoreCase(uri.getHost())) {
            throw new PermanentAgentException(
                    "PLATFORM_RESPONSE_INVALID", "Graph pagination URL points outside graph.microsoft.com");
        }
        if (page >= MAX_GRAPH_PAGES || !visited.add(next)) {
            throw new PermanentAgentException(
                    "PLATFORM_RESPONSE_INVALID", "Graph pagination did not terminate safely");
        }
    }

    private static boolean isRetryableStatus(int status) {
        return status == HttpStatus.REQUEST_TIMEOUT.value()
                || status == HttpStatus.TOO_MANY_REQUESTS.value();
    }

    private static boolean isDeviceId(String value) {
        return value != null && value.matches(
                "(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                && !"00000000-0000-0000-0000-000000000000".equalsIgnoreCase(value);
    }

    private static String stringValue(Object value) {
        return value == null ? null : value.toString();
    }

    private static int integerValue(Object value, int fallback) {
        try {
            return value == null ? fallback : Integer.parseInt(value.toString());
        } catch (NumberFormatException exception) {
            return fallback;
        }
    }

    private static List<Map<String, Object>> maps(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>(list.size());
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> raw)) {
                throw new PermanentAgentException(
                        "PLATFORM_RESPONSE_INVALID", "Graph returned a non-object list item");
            }
            Map<String, Object> mapped = new HashMap<>();
            raw.forEach((key, nestedValue) -> {
                if (key != null) {
                    mapped.put(key.toString(), nestedValue);
                }
            });
            result.add(mapped);
        }
        return result;
    }

    private List<Map<String, Object>> values(Map<String, Object> body) {
        return maps(body.get("value"));
    }
}
