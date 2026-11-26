// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

import com.certping.agent.scep.ChallengeValidationException;
import com.certping.agent.scep.IntuneUnavailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Transport for Intune's third-party-CA SCEP validation service. Mirrors what Microsoft's
 * {@code Intune-Resource-Access} library (com.microsoft.intune.scepvalidation) does, but on the
 * agent's own {@link RestTemplate} so we avoid its unreleased {@code -SNAPSHOT} jar and its retired
 * ADAL dependency.
 *
 * <p>Three steps: acquire a client-credentials token; discover the {@code ScepRequestValidationFEService}
 * base URL via Microsoft Graph (cached, it rarely changes); POST validate / success / failure to the
 * {@code ScepActions/*} suffixes. A business rejection comes back as HTTP 200 with a non-{@code Success}
 * {@code code} and becomes a {@link ChallengeValidationException}; any transport, auth, or discovery
 * failure becomes an {@link IntuneUnavailableException}.
 *
 * <p>The JSON envelopes and the token scope below are transcribed from that library's source. The
 * wrapper keys and the thumbprint/serial/expiry formats are not covered by a public REST reference,
 * so they must be confirmed once against a live tenant.
 *
 * <p>This client is shared by SCEP challenge validation and Intune revocation processing. It is
 * therefore an unconditional component even when the optional SCEP HTTP endpoint is disabled.
 */
@Slf4j
@Component
public class IntuneScepClient {

    public static final String GRAPH_SCOPE = "https://graph.microsoft.com/.default";
    public static final String MANAGE_SCOPE = "https://api.manage.microsoft.com/.default";

    private static final String TOKEN_URL = "https://login.microsoftonline.com/%s/oauth2/v2.0/token";
    private static final String INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000";
    private static final String DISCOVERY_URL =
            "https://graph.microsoft.com/v1.0/servicePrincipals/appId=" + INTUNE_APP_ID + "/endpoints";
    private static final String SERVICE_NAME = "ScepRequestValidationFEService";
    private static final String SUCCESS_CODE = "Success";
    // The manage.microsoft.com ScepActions endpoints reject any call without this header
    // (HTTP 400 MissingApiVersionHeader). Verified against a live tenant, not just the library source.
    private static final String SERVICE_API_VERSION = "2018-02-20";

    private final RestTemplate rest;

    @Autowired
    public IntuneScepClient(RestTemplateBuilder builder) {
        this(builder
                .connectTimeout(Duration.ofSeconds(5))
                .readTimeout(Duration.ofSeconds(30))
                .build());
    }

    IntuneScepClient(RestTemplate rest) {
        this.rest = rest;
    }

    // ---- token ---------------------------------------------------------------------------------

    /** Client-credentials token for {@code scope}. Any failure is transient from SCEP's point of view. */
    public String acquireToken(String tenantId, String clientId, String clientSecret, String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("scope", scope);
        form.add("grant_type", "client_credentials");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        Map<String, Object> body = exchange(String.format(TOKEN_URL, tenantId), HttpMethod.POST,
                new HttpEntity<>(form, headers), "Entra token request");
        Object token = body.get("access_token");
        if (token == null) {
            throw new IntuneUnavailableException("Entra token response contained no access_token");
        }
        return token.toString();
    }

    // ---- discovery -----------------------------------------------------------------------------

    /**
     * Finds the {@code ScepRequestValidationFEService} base URL via Graph. The result is cached by
     * the caller per Intune connection — this client is shared across tenants and holds no state.
     */
    public String discoverValidationServiceUrl(String graphToken) {
        return discoverServiceUrl(graphToken, SERVICE_NAME);
    }

    public String discoverServiceUrl(String graphToken, String serviceName) {
        HttpHeaders headers = bearer(graphToken);
        Map<String, Object> body = exchange(DISCOVERY_URL, HttpMethod.GET,
                new HttpEntity<>(headers), "Intune SCEP service discovery");

        Object value = body.get("value");
        if (value instanceof List<?> entries) {
            for (Object entry : entries) {
                if (entry instanceof Map<?, ?> endpoint && serviceName.equals(endpoint.get("providerName"))) {
                    Object uri = endpoint.get("uri");
                    if (uri != null && !uri.toString().isBlank()) {
                        log.info("Intune SCEP validation service discovered: {}", uri);
                        return uri.toString();
                    }
                }
            }
        }
        throw new IntuneUnavailableException(
                "Graph did not advertise a " + serviceName + " endpoint for this tenant");
    }

    // ---- SCEP actions --------------------------------------------------------------------------

    /** Validate the challenge. Returns normally when accepted; throws on rejection or outage. */
    public void validateRequest(String serviceUrl, String manageToken,
                                String transactionId, String csrBase64, String callerInfo) {
        Map<String, Object> request = Map.of(
                "transactionId", transactionId,
                "certificateRequest", csrBase64,
                "callerInfo", callerInfo);
        Map<String, Object> response = postAction(serviceUrl, "validateRequest", manageToken,
                Map.of("request", request), "Intune challenge validation");
        String code = code(response);
        if (code == null) {
            // Fail closed: an empty or unrecognised body is not proof of acceptance, and a caller
            // treats acceptance as licence to trust the request's device identity.
            throw new IntuneUnavailableException(
                    "Intune challenge validation returned no result code");
        }
        if (!SUCCESS_CODE.equalsIgnoreCase(code)) {
            log.warn("SCEP challenge REJECTED by Intune: txn={} code={}", transactionId, code);
            throw new ChallengeValidationException("Intune rejected the SCEP challenge: " + code);
        }
        log.debug("Intune challenge accepted: txn={}", transactionId);
    }

    public void sendSuccessNotification(String serviceUrl, String manageToken,
                                        String transactionId, String csrBase64, String thumbprint,
                                        String serial, String expiryUtcIso, String issuingAuthority,
                                        String caConfiguration, String certificateAuthority,
                                        String callerInfo) {
        Map<String, Object> notification = mapOf(
                "transactionId", transactionId,
                "certificateRequest", csrBase64,
                "certificateThumbprint", thumbprint,
                "certificateSerialNumber", serial,
                "certificateExpirationDateUtc", expiryUtcIso,
                "issuingCertificateAuthority", issuingAuthority,
                "caConfiguration", caConfiguration,
                "certificateAuthority", certificateAuthority,
                "callerInfo", callerInfo);
        requireSuccess(postAction(serviceUrl, "successNotification", manageToken,
                Map.of("notification", notification), "Intune success notification"));
        log.debug("Intune notified of issuance: txn={} serial={}", transactionId, serial);
    }

    public void sendFailureNotification(String serviceUrl, String manageToken, String transactionId,
                                        String csrBase64, long hResult, String errorDescription,
                                        String callerInfo) {
        Map<String, Object> notification = mapOf(
                "transactionId", transactionId,
                "certificateRequest", csrBase64,
                "hResult", hResult,
                "errorDescription", errorDescription,
                "callerInfo", callerInfo);
        requireSuccess(postAction(serviceUrl, "failureNotification", manageToken,
                Map.of("notification", notification), "Intune failure notification"));
        log.info("Intune notified of failure txn={} hResult=0x{}", transactionId, Long.toHexString(hResult));
    }

    // ---- internals -----------------------------------------------------------------------------

    private Map<String, Object> postAction(String serviceUrl, String action, String token,
                                           Map<String, Object> body, String description) {
        String base = serviceUrl.endsWith("/") ? serviceUrl.substring(0, serviceUrl.length() - 1) : serviceUrl;
        HttpHeaders headers = bearer(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("api-version", SERVICE_API_VERSION);
        return exchange(base + "/ScepActions/" + action, HttpMethod.POST,
                new HttpEntity<>(body, headers), description);
    }

    private Map<String, Object> exchange(String url, HttpMethod method, HttpEntity<?> entity, String description) {
        try {
            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>)
                    rest.exchange(url, method, entity, Map.class);
            return response.getBody() == null ? Map.of() : response.getBody();
        } catch (RestClientException e) {
            log.warn("Intune call unavailable ({}): status={} type={}", description,
                e instanceof org.springframework.web.client.HttpStatusCodeException status
                        ? status.getStatusCode().value() : -1,
                e.getClass().getSimpleName());
            throw new IntuneUnavailableException(description + " could not reach Intune", e);
        }
    }

    private void requireSuccess(Map<String, Object> response) {
        String code = code(response);
        if (code != null && !SUCCESS_CODE.equalsIgnoreCase(code)) {
            // A notification the service refuses is retryable, not a device-facing challenge rejection.
            throw new IntuneUnavailableException("Intune notification returned code " + code);
        }
    }

    private static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        return headers;
    }

    private static String code(Map<String, Object> response) {
        Object code = response.get("code");
        return code == null ? null : code.toString();
    }

    private static Map<String, Object> mapOf(Object... kv) {
        java.util.LinkedHashMap<String, Object> map = new java.util.LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put((String) kv[i], kv[i + 1] == null ? "" : kv[i + 1]);
        }
        return map;
    }
}
