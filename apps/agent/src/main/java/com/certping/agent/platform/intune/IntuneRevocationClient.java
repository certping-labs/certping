// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.scep.IntuneUnavailableException;
import com.certping.agent.scep.intune.IntuneScepClient;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Modernized adapter for Microsoft's source-distributed Intune revocation client.
 *
 * <p>The endpoint names and payloads intentionally match Microsoft's open-source
 * {@code com.microsoft.intune.scepvalidation.IntuneRevocationClient}; authentication and HTTP
 * handling use the agent's current MSAL-based infrastructure instead of that project's legacy
 * ADAL/Apache HTTP dependencies. Keep contract tests aligned with the Microsoft source before
 * changing the service version, headers, or payload shape.
 */
@Component
public class IntuneRevocationClient {
    private static final String SERVICE_NAME = "PkiConnectorFEService";
    private static final String API_VERSION = "5019-05-05";
    private static final String DOWNLOAD = "CertificateAuthorityRequests/downloadRevocationRequests";
    private static final String UPLOAD = "CertificateAuthorityRequests/uploadRevocationResults";
    private static final Set<String> ERROR_CODES = Set.of(
            "0", "4000", "4001", "4002", "4003", "4004", "4005", "4006", "4007",
            "4100", "4101", "4102", "4103");

    private final DeviceSourceCredentialRegistry credentialRegistry;
    private final IntuneScepClient intuneClient;
    private final ObjectMapper objectMapper;
    private final RestTemplate rest;

    public IntuneRevocationClient(DeviceSourceCredentialRegistry credentialRegistry,
                                  IntuneScepClient intuneClient,
                                  ObjectMapper objectMapper,
                                  RestTemplateBuilder builder) {
        this.credentialRegistry = credentialRegistry;
        this.intuneClient = intuneClient;
        this.objectMapper = objectMapper;
        this.rest = builder.connectTimeout(Duration.ofSeconds(5))
                .readTimeout(Duration.ofSeconds(30)).build();
    }

    public List<RevocationRequest> download(String profileRef, String transactionId, int maxRequests) {
        if (maxRequests < 1 || maxRequests > 100) {
            throw new PermanentAgentException("INTUNE_REVOCATION_REQUEST_INVALID",
                    "maxRequests must be between 1 and 100");
        }
        Session session = session(profileRef);
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("maxRequests", maxRequests);
        parameters.put("issuerName", null);
        Map<String, Object> response = post(session, DOWNLOAD, transactionId,
                Map.of("downloadParameters", parameters));
        Object value = response.get("value");
        if (!(value instanceof List<?>)) return List.of();
        return objectMapper.convertValue(value, new TypeReference<>() {});
    }

    public void upload(String profileRef, String transactionId, List<RevocationResult> results) {
        if (results == null || results.isEmpty() || results.size() > 100) {
            throw new PermanentAgentException("INTUNE_REVOCATION_RESULT_INVALID",
                    "Intune revocation upload must contain between 1 and 100 results");
        }
        for (RevocationResult result : results) {
            if (result == null || blank(result.requestContext())
                    || result.requestContext().length() > 1000
                    || !ERROR_CODES.contains(result.errorCode())
                    || (result.succeeded() && !"0".equals(result.errorCode()))
                    || (!result.succeeded() && "0".equals(result.errorCode()))) {
                throw new PermanentAgentException("INTUNE_REVOCATION_RESULT_INVALID",
                        "Intune revocation result does not follow the connector contract");
            }
        }
        Session session = session(profileRef);
        Map<String, Object> response = post(session, UPLOAD, transactionId,
                Map.of("results", results));
        if (!Boolean.TRUE.equals(response.get("value"))) {
            throw new TransientAgentException("INTUNE_REVOCATION_UPLOAD_REJECTED",
                    "Intune did not accept the revocation result upload");
        }
    }

    private Session session(String profileRef) {
        try {
            Map<String, Object> credentials = objectMapper.readValue(
                    credentialRegistry.requireCredentialsJson(profileRef, DevicePlatformType.INTUNE),
                    new TypeReference<>() {});
            String tenant = required(credentials.get("tenantId"));
            String clientId = required(credentials.get("clientId"));
            String secret = required(credentials.get("clientSecret"));
            String graphToken = intuneClient.acquireToken(
                    tenant, clientId, secret, IntuneScepClient.GRAPH_SCOPE);
            String manageToken = intuneClient.acquireToken(
                    tenant, clientId, secret, IntuneScepClient.MANAGE_SCOPE);
            String serviceUrl = intuneClient.discoverServiceUrl(graphToken, SERVICE_NAME);
            return new Session(serviceUrl, manageToken);
        } catch (PermanentAgentException exception) {
            throw exception;
        } catch (IntuneUnavailableException exception) {
            throw new TransientAgentException("INTUNE_REVOCATION_UNAVAILABLE",
                    "Could not authenticate to or discover the Intune revocation service", exception);
        } catch (Exception exception) {
            throw new PermanentAgentException("PLATFORM_NOT_CONFIGURED",
                    "Could not load Intune revocation credentials", exception);
        }
    }

    private Map<String, Object> post(Session session, String path,
                                     String transactionId, Map<String, ?> body) {
        String base = session.serviceUrl().endsWith("/")
                ? session.serviceUrl().substring(0, session.serviceUrl().length() - 1)
                : session.serviceUrl();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(session.manageToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.set("api-version", API_VERSION);
        headers.set("client-request-id", transactionId);
        headers.set("UserAgent", "CertPingAgent/1");
        try {
            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response =
                    (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) rest.exchange(
                            base + "/" + path, HttpMethod.POST,
                            new HttpEntity<>(body, headers), Map.class);
            return response.getBody() == null ? Map.of() : response.getBody();
        } catch (HttpClientErrorException exception) {
            if (exception.getStatusCode().value() == 408
                    || exception.getStatusCode().value() == 429) {
                throw new TransientAgentException("INTUNE_REVOCATION_THROTTLED",
                        "Intune revocation endpoint is temporarily unavailable", exception);
            }
            throw new PermanentAgentException("INTUNE_REVOCATION_REJECTED",
                    "Intune rejected the revocation request: " + exception.getStatusCode(), exception);
        } catch (HttpServerErrorException | ResourceAccessException exception) {
            throw new TransientAgentException("INTUNE_REVOCATION_UNAVAILABLE",
                    "Could not reach the Intune revocation endpoint", exception);
        }
    }

    private static String required(Object value) {
        if (value == null || value.toString().isBlank()) {
            throw new PermanentAgentException("PLATFORM_NOT_CONFIGURED",
                    "Intune credentials are incomplete");
        }
        return value.toString().trim();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private record Session(String serviceUrl, String manageToken) {}

    public record RevocationRequest(String requestContext, String serialNumber,
                                    String issuerName, String caConfiguration) {}
    public record RevocationResult(String requestContext, boolean succeeded,
                                   String errorCode, String errorMessage) {}
}
