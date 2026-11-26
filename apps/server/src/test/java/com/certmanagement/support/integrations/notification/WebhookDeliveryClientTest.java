// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

class WebhookDeliveryClientTest {

    private RestClient restClient;
    private RestClient.RequestBodyUriSpec postSpec;
    private RestClient.ResponseSpec responseSpec;
    private WebhookDeliveryClient client;

    private static final URI URL = URI.create("https://hooks.example.com/x");

    @BeforeEach
    void setUp() {
        restClient = mock(RestClient.class);
        postSpec = mock(RestClient.RequestBodyUriSpec.class);
        responseSpec = mock(RestClient.ResponseSpec.class);

        lenient().doReturn(postSpec).when(restClient).post();
        lenient().doReturn(postSpec).when(postSpec).uri(any(URI.class));
        lenient().doReturn(postSpec).when(postSpec).contentType(any());
        lenient().doReturn(postSpec).when(postSpec).body(any(Object.class));
        lenient().doReturn(responseSpec).when(postSpec).retrieve();

        client = new WebhookDeliveryClient(restClient);
    }

    @Test
    void deliver_success_emptyBody() {
        when(responseSpec.toEntity(String.class)).thenReturn(new ResponseEntity<>("", HttpStatus.OK));
        assertThatCode(() -> client.deliver(IntegrationProvider.SLACK, URL, Map.of("text", "hi")))
                .doesNotThrowAnyException();
    }

    @Test
    void deliver_success_benignBody() {
        when(responseSpec.toEntity(String.class)).thenReturn(new ResponseEntity<>("ok", HttpStatus.OK));
        assertThatCode(() -> client.deliver(IntegrationProvider.TEAMS, URL, Map.of("text", "hi")))
                .doesNotThrowAnyException();
    }

    @Test
    void deliver_embeddedError_throws502() {
        when(responseSpec.toEntity(String.class))
                .thenReturn(new ResponseEntity<>("{\"error\":\"invalid_payload\"}", HttpStatus.OK));

        ApiException ex = catchThrowableOfType(
                () -> client.deliver(IntegrationProvider.SLACK, URL, Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.code()).isEqualTo("INTEGRATION_NOTIFICATION_DELIVERY_FAILED");
    }

    @Test
    void deliver_teamsEmbeddedFailure_specialMessage() {
        when(responseSpec.toEntity(String.class))
                .thenReturn(new ResponseEntity<>("channel does not belong to team", HttpStatus.OK));

        ApiException ex = catchThrowableOfType(
                () -> client.deliver(IntegrationProvider.TEAMS, URL, Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.getMessage()).contains("downstream failure");
    }

    @Test
    void deliver_responseException_throws502() {
        when(responseSpec.toEntity(String.class))
                .thenThrow(new RestClientResponseException(
                        "bad", HttpStatus.BAD_GATEWAY, "Bad", new HttpHeaders(), null, null));

        ApiException ex = catchThrowableOfType(
                () -> client.deliver(IntegrationProvider.SLACK, URL, Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
    }

    @Test
    void deliver_timeout_throws504() {
        when(responseSpec.toEntity(String.class)).thenThrow(new ResourceAccessException("timeout"));

        ApiException ex = catchThrowableOfType(
                () -> client.deliver(IntegrationProvider.SLACK, URL, Map.of()), ApiException.class);
        assertThat(ex.status()).isEqualTo(504);
        assertThat(ex.code()).isEqualTo("INTEGRATION_NOTIFICATION_TIMEOUT");
    }

    @Test
    void deliver_downstreamBodyIsLoggedNotReturnedToTheCaller() {
        String secret = "{\"error\":\"internal-service-says: db-password=hunter2\"}";
        when(responseSpec.toEntity(String.class)).thenReturn(new ResponseEntity<>(secret, HttpStatus.OK));

        ApiException ex = catchThrowableOfType(
                () -> client.deliver(IntegrationProvider.SLACK, URL, Map.of()), ApiException.class);

        assertThat(ex.status()).isEqualTo(502);
        assertThat(String.valueOf(ex.details())).contains("downstreamStatus").doesNotContain("hunter2");
        assertThat(ex.getMessage()).doesNotContain("hunter2");
    }
}
