// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.notification;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.common.RequestContext;
import com.certmanagement.support.config.GuardedHttpClients;
import lombok.extern.slf4j.Slf4j;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

@Slf4j
@Component
public class WebhookDeliveryClient {

    private final RestClient restClient;

    public WebhookDeliveryClient(@Qualifier("integrationWebhookRestClient") RestClient integrationWebhookRestClient) {
        this.restClient = integrationWebhookRestClient;
    }

    public void deliver(IntegrationProvider provider, URI webhookUrl, Object payload) {
        long startedAt = System.nanoTime();
        HttpServletRequest currentRequest = RequestContext.currentRequest();
        String downstreamService = provider.name().toLowerCase() + "-webhook";
        try {
            // Retries stay outside this service so the caller can decide idempotency, backoff,
            // and audit semantics. This client performs a single bounded delivery attempt.
            ResponseEntity<String> response = restClient.post()
                    .uri(webhookUrl)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(payload)
                    .retrieve()
                    .toEntity(String.class);
            RequestContext.recordDownstreamCall(currentRequest, downstreamService, response.getStatusCode().value(), elapsedMillis(startedAt));
            failIfSuccessfulStatusContainsError(provider, response);
        } catch (RestClientResponseException exception) {
            RequestContext.recordDownstreamCall(currentRequest, downstreamService, exception.getStatusCode().value(), elapsedMillis(startedAt));
            throw new ApiException(502, "INTEGRATION_NOTIFICATION_DELIVERY_FAILED", "Notification delivery failed");
        } catch (ResourceAccessException exception) {
            RequestContext.recordDownstreamCall(currentRequest, downstreamService, null, elapsedMillis(startedAt));
            if (refusedAddress(exception)) {
                log.warn("Webhook delivery refused provider={} host={}: resolves to a private or internal address",
                        provider, webhookUrl.getHost());
                throw new ApiException(502, "INTEGRATION_DESTINATION_REFUSED",
                        "Notification destination resolves to a private or internal address");
            }
            throw new ApiException(504, "INTEGRATION_NOTIFICATION_TIMEOUT", "Notification delivery timed out");
        }
    }

    static boolean refusedAddress(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof GuardedHttpClients.BlockedAddressException) {
                return true;
            }
        }
        return false;
    }

    private long elapsedMillis(long startedAt) {
        return (System.nanoTime() - startedAt) / 1_000_000L;
    }

    private void failIfSuccessfulStatusContainsError(IntegrationProvider provider, ResponseEntity<String> response) {
        String responseBody = response.getBody();
        if (!StringUtils.hasText(responseBody)) {
            return;
        }

        String normalizedBody = responseBody.toLowerCase();
        boolean hasEmbeddedFailure = normalizedBody.contains("\"error\"")
                || normalizedBody.contains("\"code\"")
                || normalizedBody.contains("action '")
                || normalizedBody.contains("failed:")
                || normalizedBody.contains("channel does not belong to team");
        if (!hasEmbeddedFailure) {
            return;
        }

        // The body stays in the log: it is whatever the destination answered, and echoing it to the API
        // caller would turn the webhook into a way to read arbitrary responses.
        log.warn("Webhook delivery reported a downstream failure provider={} status={} body={}",
                provider, response.getStatusCode().value(), truncated(responseBody));
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("downstreamStatus", response.getStatusCode().value());
        throw new ApiException(
                502,
                "INTEGRATION_NOTIFICATION_DELIVERY_FAILED",
                failureMessage(provider),
                details);
    }

    private String failureMessage(IntegrationProvider provider) {
        if (provider == IntegrationProvider.TEAMS) {
            return "Teams workflow accepted the request but reported a downstream failure";
        }
        return "Notification delivery failed";
    }

    private String truncated(String value) {
        if (value.length() <= 1000) {
            return value;
        }
        return value.substring(0, 1000);
    }
}
