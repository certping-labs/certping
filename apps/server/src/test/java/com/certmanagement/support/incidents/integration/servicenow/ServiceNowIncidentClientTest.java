// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.integration.servicenow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.config.IncidentsProperties;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

class ServiceNowIncidentClientTest {

    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();
    private static final URI INSTANCE = URI.create("https://dev.service-now.com");

    private RestClient.Builder builder;
    private RestClient restClient;
    private RestClient.RequestBodyUriSpec postSpec;
    private RestClient.ResponseSpec responseSpec;
    private ServiceNowIncidentClient client;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        builder = mock(RestClient.Builder.class);
        restClient = mock(RestClient.class);
        postSpec = mock(RestClient.RequestBodyUriSpec.class);
        responseSpec = mock(RestClient.ResponseSpec.class);

        lenient().when(builder.clone()).thenReturn(builder);
        lenient().when(builder.baseUrl(anyString())).thenReturn(builder);
        lenient().when(builder.requestFactory(any())).thenReturn(builder);
        lenient().when(builder.defaultHeader(anyString(), any(String[].class))).thenReturn(builder);
        lenient().when(builder.build()).thenReturn(restClient);

        lenient().doReturn(postSpec).when(restClient).post();
        lenient().doReturn(postSpec).when(postSpec).uri(anyString());
        lenient().doReturn(postSpec).when(postSpec).contentType(any());
        lenient().doReturn(postSpec).when(postSpec).body(any(Object.class));
        lenient().doReturn(postSpec).when(postSpec).headers(any());
        lenient().doReturn(responseSpec).when(postSpec).retrieve();

        IncidentsProperties.ServiceNow snProps = new IncidentsProperties.ServiceNow(
                Duration.ofSeconds(5), Duration.ofSeconds(5));
        IncidentsProperties props = new IncidentsProperties(
                new IncidentsProperties.PagerDuty(URI.create("https://events.pagerduty.com"),
                        Duration.ofSeconds(5), Duration.ofSeconds(5)),
                snProps);

        client = new ServiceNowIncidentClient(builder, props);
    }

    private JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Map<String, String> secrets() {
        return Map.of("client_id", "cid", "client_secret", "csec");
    }

    private Map<String, Object> body() {
        return Map.of("short_description", "hello");
    }

    // Make the headers(...) callback actually execute so token fetch runs.
    @SuppressWarnings("unchecked")
    private void wireHeaderCallbackExecution() {
        doAnswer(inv -> {
            Consumer<HttpHeaders> consumer = inv.getArgument(0);
            consumer.accept(new HttpHeaders());
            return postSpec;
        }).when(postSpec).headers(any());
    }

    @Test
    void createIncident_success() {
        wireHeaderCallbackExecution();
        // token fetch returns access token; incident create returns result
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenReturn(new ServiceNowAccessTokenResponse("tok-123", "Bearer"));
        when(responseSpec.body(JsonNode.class))
                .thenReturn(json("{\"result\":{\"sys_id\":\"abc123\",\"number\":\"INC001\"}}"));

        ServiceNowIncidentClient.ServiceNowIncidentCreateResult result =
                client.createIncident(INSTANCE, "useraccount", body(), secrets());

        assertThat(result.sysId()).isEqualTo("abc123");
        assertThat(result.number()).isEqualTo("INC001");
        assertThat(result.recordUrl()).contains("/api/now/v1/table/incident/abc123");
        assertThat(result.displayUrl()).contains("sys_id=abc123");
    }

    @Test
    void createIncident_missingSysId_throws502() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenReturn(new ServiceNowAccessTokenResponse("tok-123", "Bearer"));
        when(responseSpec.body(JsonNode.class))
                .thenReturn(json("{\"result\":{\"number\":\"INC001\"}}"));

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.code()).isEqualTo("SERVICENOW_REQUEST_FAILED");
    }

    @Test
    void createIncident_missingSecret_throws500() {
        wireHeaderCallbackExecution();
        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), Map.of("client_id", "cid")),
                ApiException.class);
        assertThat(ex.status()).isEqualTo(500);
        assertThat(ex.code()).isEqualTo("INTEGRATION_SECRET_REFERENCE_INVALID");
    }

    @Test
    void createIncident_tokenResponseNull_throws502() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class)).thenReturn(null);

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.code()).isEqualTo("SERVICENOW_REQUEST_FAILED");
    }

    @Test
    void createIncident_tokenResponseException_throws502() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenThrow(new RestClientResponseException(
                        "bad", HttpStatus.UNAUTHORIZED, "Unauthorized", new HttpHeaders(), null, null));

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
    }

    @Test
    void createIncident_tokenTimeout_throws504() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenThrow(new ResourceAccessException("timeout"));

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, "useraccount", body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(504);
        assertThat(ex.code()).isEqualTo("SERVICENOW_REQUEST_TIMEOUT");
    }

    @Test
    void createIncident_tokenParseError_throws502() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenThrow(new RestClientException("parse"));

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
    }

    @Test
    void createIncident_createResponseException_throws502() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenReturn(new ServiceNowAccessTokenResponse("tok-123", "Bearer"));
        when(responseSpec.body(JsonNode.class))
                .thenThrow(new RestClientResponseException(
                        "bad", HttpStatus.BAD_GATEWAY, "Bad", new HttpHeaders(), null, null));

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
        assertThat(ex.code()).isEqualTo("SERVICENOW_REQUEST_FAILED");
    }

    @Test
    void createIncident_createTimeout_throws504() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenReturn(new ServiceNowAccessTokenResponse("tok-123", "Bearer"));
        when(responseSpec.body(JsonNode.class)).thenThrow(new ResourceAccessException("timeout"));

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(504);
        assertThat(ex.code()).isEqualTo("SERVICENOW_REQUEST_TIMEOUT");
    }

    @Test
    void createIncident_createParseError_throws502() {
        wireHeaderCallbackExecution();
        when(responseSpec.body(ServiceNowAccessTokenResponse.class))
                .thenReturn(new ServiceNowAccessTokenResponse("tok-123", "Bearer"));
        when(responseSpec.body(JsonNode.class)).thenThrow(new RestClientException("parse"));

        ApiException ex = catchThrowableOfType(
                () -> client.createIncident(INSTANCE, null, body(), secrets()), ApiException.class);
        assertThat(ex.status()).isEqualTo(502);
    }
}
