// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.integration.pagerduty;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.common.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

@Component
public class PagerDutyEventsClient {

    private final RestClient restClient;

    public PagerDutyEventsClient(@Qualifier("pagerDutyEventsRestClient") RestClient restClient) {
        this.restClient = restClient;
    }

    public PagerDutyEnqueueResponse triggerIncident(Map<String, Object> payload) {
        long startedAt = System.nanoTime();
        HttpServletRequest currentRequest = RequestContext.currentRequest();
        try {
            ResponseEntity<PagerDutyEnqueueResponse> response = restClient.post()
                    .uri("/v2/enqueue")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(payload)
                    .retrieve()
                    .toEntity(PagerDutyEnqueueResponse.class);
            RequestContext.recordDownstreamCall(currentRequest, "pagerduty-events", response.getStatusCode().value(), elapsedMillis(startedAt));
            PagerDutyEnqueueResponse body = response.getBody();
            if (body == null || body.status() == null || body.message() == null) {
                throw new ApiException(502, "PAGERDUTY_REQUEST_FAILED", "PagerDuty incident request failed");
            }
            return body;
        } catch (RestClientResponseException exception) {
            RequestContext.recordDownstreamCall(currentRequest, "pagerduty-events", exception.getStatusCode().value(), elapsedMillis(startedAt));
            throw new ApiException(502, "PAGERDUTY_REQUEST_FAILED", "PagerDuty incident request failed");
        } catch (ResourceAccessException exception) {
            RequestContext.recordDownstreamCall(currentRequest, "pagerduty-events", null, elapsedMillis(startedAt));
            throw new ApiException(504, "PAGERDUTY_REQUEST_TIMEOUT", "PagerDuty incident request timed out");
        }
    }

    private long elapsedMillis(long startedAt) {
        return (System.nanoTime() - startedAt) / 1_000_000L;
    }
}
