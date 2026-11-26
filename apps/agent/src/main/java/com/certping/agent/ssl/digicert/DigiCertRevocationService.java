// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.digicert;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.Optional;

/**
 * Revokes a DigiCert certificate via DigiCert Services API v2.
 *
 * <p>Network errors are {@link TransientAgentException} (redelivery). Most 4xx responses are
 * {@link PermanentAgentException}. HTTP 422 with "already revoked" is treated as success (idempotent).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DigiCertRevocationService {

    private final AgentProperties agentProperties;

    /**
     * @param orderId DigiCert order ID
     * @param reason  RFC 5280 reason string — normalized to DigiCert's lowercase, no-underscore form
     * @param apiKey  DigiCert API key (X-DC-DEVKEY)
     */
    public void revoke(String orderId, String reason, String apiKey) {
        if (orderId == null || orderId.isBlank()) {
            throw new PermanentAgentException("MISSING_ORDER_ID",
                    "DigiCert orderId is required for revocation — cert entity may be missing orderId");
        }
        if (apiKey == null || apiKey.isBlank()) {
            throw new PermanentAgentException("MISSING_CA_CREDENTIAL",
                    "DigiCert API key is required for revocation");
        }

        String base = agentProperties.getDigicert().getApiBaseUrl();
        String url = base + "/order/certificate/" + orderId + "/status";

        String dcReason = reason != null
                ? reason.toLowerCase().replace("_", "")
                : "unspecified";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-DC-DEVKEY", DigiCertApiKey.from(apiKey));

        Map<String, String> body = Map.of(
                "status", "revoked",
                "revocation_reason", dcReason);

        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.PUT, new HttpEntity<>(body, headers), String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("[DigiCertRevocation] Order {} revoked successfully, reason={}", orderId, dcReason);
                return;
            }
            throw new PermanentAgentException("REVOCATION_FAILED",
                    "DigiCert returned unexpected status: " + response.getStatusCode()
                            + " for order: " + orderId);

        } catch (HttpClientErrorException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("digicert revocation", orderId, e);
            }
            int code = e.getStatusCode().value();
            String responseBody = e.getResponseBodyAsString();
            String bodyLower = responseBody != null ? responseBody.toLowerCase() : "";

            if (code == 404) {
                throw new PermanentAgentException("ORDER_NOT_FOUND",
                        "DigiCert order not found: " + orderId);
            }
            if (code == 401 || code == 403) {
                throw new PermanentAgentException("REVOCATION_UNAUTHORIZED",
                        "Unauthorized for DigiCert revocation, order: " + orderId);
            }
            if (code == 422 && bodyLower.contains("already revoked")) {
                log.info("[DigiCertRevocation] Order {} already revoked at DigiCert — treating as success", orderId);
                return;
            }
            if (code == 422) {
                throw new PermanentAgentException("REVOCATION_INVALID_STATE",
                        "DigiCert revocation rejected for order " + orderId + ": " + responseBody, e);
            }
            throw new PermanentAgentException("REVOCATION_FAILED",
                    "DigiCert API error " + e.getStatusCode()
                            + " for order " + orderId + ": " + responseBody, e);

        } catch (PermanentAgentException | RetryableAgentException e) {
            throw e;
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("digicert revocation", orderId, e);
            }
            throw new TransientAgentException("REVOCATION_TRANSIENT",
                    "Network error revoking DigiCert order " + orderId + ": " + e.getMessage(), e);
        }
    }
}
