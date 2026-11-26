// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class HostingerDnsProviderTest {

    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockResponse;

    private HostingerDnsProvider provider;

    @BeforeEach
    void setUp() {
        provider = new HostingerDnsProvider("test-api-token");
        ReflectionTestUtils.setField(provider, "httpClient", mockHttpClient);
    }

    // ── constructor validation ────────────────────────────────────────────────

    @Test
    void constructor_blankApiToken_throwsPermanentException() {
        assertThatThrownBy(() -> new HostingerDnsProvider("  "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── addTxtRecord ──────────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_success_returnsHostScopedRecordId() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest");

        assertThat(recordId).isEqualTo("_acme-challenge:example.com:digest");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_created201_isTreatedAsSuccess() throws Exception {
        when(mockResponse.statusCode()).thenReturn(201);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThat(provider.addTxtRecord("_acme-challenge.example.com", "digest"))
                .isEqualTo("_acme-challenge:example.com:digest");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_authFailed_throwsPermanentException() throws Exception {
        when(mockResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_AUTH_FAILED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_forbidden_throwsPermanentException() throws Exception {
        when(mockResponse.statusCode()).thenReturn(403);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_rateLimited_throwsRetryableException() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"))
                .hasMessageContaining("rate-limited");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_rateLimitedWithRetryAfter_preservesRetryAfter() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockResponse.headers()).thenReturn(java.net.http.HttpHeaders.of(
                Map.of("Retry-After", List.of("60")), (name, value) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getRetryAfter())
                        .isEqualTo(Duration.ofSeconds(60)));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_serverError_throwsTransientException() throws Exception {
        when(mockResponse.statusCode()).thenReturn(500);
        when(mockResponse.body()).thenReturn("Internal Server Error");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_networkException_throwsTransientException() throws Exception {
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.io.IOException("Connection refused"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class);
    }

    // ── deleteTxtRecord ───────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_success_doesNotThrow() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_notFound_doesNotThrow() throws Exception {
        when(mockResponse.statusCode()).thenReturn(404);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com");
    }

    @Test
    void deleteTxtRecord_invalidRecordIdFormat_skipsRequest() {
        provider.deleteTxtRecord("_acme-challenge.example.com", "invalid-no-colon");
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_httpError_doesNotThrow() throws Exception {
        when(mockResponse.statusCode()).thenReturn(500);
        when(mockResponse.body()).thenReturn("Error");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_rateLimited_throwsRetryableException() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.deleteTxtRecord(
                "_acme-challenge.example.com", "_acme-challenge:example.com"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_networkException_doesNotThrow() throws Exception {
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.io.IOException("Connection refused"));

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_otherValueAtTheName_rewritesTheSetWithIt() throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "[{\"name\":\"@\",\"type\":\"TXT\",\"ttl\":300,"
                        + "\"records\":[{\"content\":\"v=spf1 -all\"}]},"
                        + "{\"name\":\"_acme-challenge\",\"type\":\"TXT\",\"ttl\":300,"
                        + "\"records\":[{\"content\":\"\\\"apex-digest\\\"\"},{\"content\":\"wildcard-digest\"}]}]"))
                .thenReturn(response(200, ""));

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com:apex-digest");

        HttpRequest put = request.getAllValues().get(1);
        assertThat(put.method()).isEqualTo("PUT");
        JsonNode body = JsonMapper.builderWithJackson2Defaults().build().readTree(HttpRequestBodies.bodyOf(put));
        assertThat(body.path("overwrite").asBoolean()).isTrue();
        JsonNode zone = body.path("zone").get(0);
        assertThat(zone.path("name").asString()).isEqualTo("_acme-challenge");
        assertThat(zone.path("records").findValues("content").stream().map(JsonNode::asString).toList())
                .containsExactly("wildcard-digest");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_lastValue_deletesTheSet() throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "[{\"name\":\"_acme-challenge\",\"type\":\"TXT\",\"ttl\":300,"
                        + "\"records\":[{\"content\":\"digest\"}]}]"))
                .thenReturn(response(200, ""));

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com:digest");

        assertThat(request.getAllValues()).extracting(HttpRequest::method).containsExactly("GET", "DELETE");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_valueNotThere_changesNothing() throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "[]"));

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com:digest");

        assertThat(request.getAllValues()).extracting(HttpRequest::method).containsExactly("GET");
    }

    private static HttpResponse<String> response(int status, String body) {
        return new HttpResponse<>() {
            public int statusCode() { return status; }
            public String body() { return body; }
            public HttpRequest request() { return null; }
            public java.util.Optional<HttpResponse<String>> previousResponse() { return java.util.Optional.empty(); }
            public java.net.http.HttpHeaders headers() { return java.net.http.HttpHeaders.of(Map.of(), (k, v) -> true); }
            public java.util.Optional<javax.net.ssl.SSLSession> sslSession() { return java.util.Optional.empty(); }
            public java.net.URI uri() { return null; }
            public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    @Test
    @SuppressWarnings("unchecked")
    void addRecord_cname_sendsTheCnameTypeAndTarget() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);

        String recordId = provider.addRecord(DnsRecordType.CNAME, "_0a1b.shop.example.com", "aa.bb.dcv.example");

        assertThat(recordId).isEqualTo("_0a1b.shop:example.com");
        JsonNode zone = JsonMapper.builderWithJackson2Defaults().build()
                .readTree(HttpRequestBodies.bodyOf(request.getValue())).path("zone").get(0);
        assertThat(zone.path("type").asString()).isEqualTo("CNAME");
        assertThat(zone.path("name").asString()).isEqualTo("_0a1b.shop");
        assertThat(zone.path("records").get(0).path("content").asString()).isEqualTo("aa.bb.dcv.example");
    }
}
