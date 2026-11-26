// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.integration.pagerduty;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.certmanagement.support.common.ApiException;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

class PagerDutyEventsClientTest {

    private RestClient restClient;
    private RestClient.RequestBodyUriSpec postSpec;
    private RestClient.ResponseSpec responseSpec;
    private PagerDutyEventsClient client;

    @BeforeEach
    void setUp() {
        restClient = mock(RestClient.class);
        postSpec = mock(RestClient.RequestBodyUriSpec.class);
        responseSpec = mock(RestClient.ResponseSpec.class);

        lenient().doReturn(postSpec).when(restClient).post();
        lenient().doReturn(postSpec).when(postSpec).uri(anyString());
        lenient().doReturn(postSpec).when(postSpec).contentType(any());
        lenient().doReturn(postSpec).when(postSpec).body(any(Object.class));
        lenient().doReturn(responseSpec).when(postSpec).retrieve();

        client = new PagerDutyEventsClient(restClient);
    }

    @Test
    void triggerIncident_success() {
        when(responseSpec.toEntity(PagerDutyEnqueueResponse.class))
                .thenReturn(new ResponseEntity<>(
                        new PagerDutyEnqueueResponse("success", "Event processed", "dk-1"),
                        HttpStatus.ACCEPTED));

        PagerDutyEnqueueResponse response = client.triggerIncident(Map.of("routing_key", "x"));
        assertThat(response.status()).isEqualTo("success");
        assertThat(response.dedupKey()).isEqualTo("dk-1");
    }

    @Test
    void triggerIncident_nullBody_throws502() {
        when(responseSpec.toEntity(PagerDutyEnqueueResponse.class))
                .thenReturn(ResponseEntity.status(HttpStatus.ACCEPTED).body(null));

        ApiException ex = catchThrowableOfType(
                () -> client.triggerIncident(Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.code()).isEqualTo("PAGERDUTY_REQUEST_FAILED");
    }

    @Test
    void triggerIncident_missingStatus_throws502() {
        when(responseSpec.toEntity(PagerDutyEnqueueResponse.class))
                .thenReturn(new ResponseEntity<>(
                        new PagerDutyEnqueueResponse(null, "msg", "dk"), HttpStatus.ACCEPTED));

        ApiException ex = catchThrowableOfType(
                () -> client.triggerIncident(Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
    }

    @Test
    void triggerIncident_responseException_throws502() {
        when(responseSpec.toEntity(PagerDutyEnqueueResponse.class))
                .thenThrow(new RestClientResponseException(
                        "bad", HttpStatus.BAD_REQUEST, "Bad", new HttpHeaders(), null, null));

        ApiException ex = catchThrowableOfType(
                () -> client.triggerIncident(Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.code()).isEqualTo("PAGERDUTY_REQUEST_FAILED");
    }

    @Test
    void triggerIncident_timeout_throws504() {
        when(responseSpec.toEntity(PagerDutyEnqueueResponse.class))
                .thenThrow(new ResourceAccessException("timeout"));

        ApiException ex = catchThrowableOfType(
                () -> client.triggerIncident(Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(504);
        assertThat(ex.code()).isEqualTo("PAGERDUTY_REQUEST_TIMEOUT");
    }
}
