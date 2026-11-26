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
import java.net.http.HttpHeaders;
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
class GoDaddyDnsProviderTest {

    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockResponse;

    private GoDaddyDnsProvider provider;

    @BeforeEach
    void setUp() {
        provider = new GoDaddyDnsProvider("test-api-key", "test-api-secret");
        ReflectionTestUtils.setField(provider, "httpClient", mockHttpClient);
    }

    // ── constructor validation ────────────────────────────────────────────────

    @Test
    void constructor_blankApiKey_throwsPermanentException() {
        assertThatThrownBy(() -> new GoDaddyDnsProvider("", "secret"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void constructor_blankApiSecret_throwsPermanentException() {
        assertThatThrownBy(() -> new GoDaddyDnsProvider("key", "   "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── addTxtRecord ──────────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_success_returnsRecordId() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest");

        // GoDaddy recordId is "host:domain"
        assertThat(recordId).contains("example.com");
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
    void addTxtRecord_serverError_throwsTransientException() throws Exception {
        when(mockResponse.statusCode()).thenReturn(500);
        when(mockResponse.body()).thenReturn("Internal Server Error");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_networkException_throwsTransientException() throws Exception {
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.io.IOException("Connection refused"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_rateLimited_throwsRetryableWithDnsProviderThrottled() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockResponse.headers()).thenReturn(
                HttpHeaders.of(Map.of("Retry-After", List.of("60")), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(ex -> {
                    RetryableAgentException r = (RetryableAgentException) ex;
                    assertThat(r.getErrorCode()).isEqualTo("DNS_PROVIDER_THROTTLED");
                    assertThat(r.getRetryAfter()).isEqualTo(Duration.ofSeconds(60));
                });
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
    void deleteTxtRecord_noContent_doesNotThrow() throws Exception {
        when(mockResponse.statusCode()).thenReturn(204);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com");
    }

    @Test
    void deleteTxtRecord_invalidRecordIdFormat_skipsRequest() {
        // recordId without ":" — invalid format, should log and return without HTTP call
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

        // Should not throw — deletion is best-effort
        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_networkException_doesNotThrow() throws Exception {
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.io.IOException("Connection refused"));

        // Should not throw — deletion is best-effort
        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_serviceUnavailable_throwsRetryable() throws Exception {
        when(mockResponse.statusCode()).thenReturn(503);
        when(mockResponse.headers()).thenReturn(
                HttpHeaders.of(Map.of(), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> {
                    RetryableAgentException r = (RetryableAgentException) e;
                    assertThat(r.getErrorCode()).isEqualTo("DNS_PROVIDER_THROTTLED");
                    assertThat(r.getMessage()).contains("no Retry-After supplied");
                });
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_throttledWithMalformedRetryAfter_ignoresHeader() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockResponse.headers()).thenReturn(
                HttpHeaders.of(Map.of("Retry-After", List.of("not-a-number")), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getRetryAfter()).isNull());
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_rateLimited_throwsRetryable() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockResponse.headers()).thenReturn(
                HttpHeaders.of(Map.of("Retry-After", List.of("30")), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.deleteTxtRecord(
                "_acme-challenge.example.com", "_acme-challenge:example.com"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> {
                    RetryableAgentException r = (RetryableAgentException) e;
                    assertThat(r.getErrorCode()).isEqualTo("DNS_PROVIDER_THROTTLED");
                    assertThat(r.getRetryAfter()).isEqualTo(Duration.ofSeconds(30));
                });
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_serviceUnavailable_throwsRetryable() throws Exception {
        when(mockResponse.statusCode()).thenReturn(503);
        when(mockResponse.headers()).thenReturn(HttpHeaders.of(Map.of(), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.deleteTxtRecord(
                "_acme-challenge.example.com", "_acme-challenge:example.com"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_wildcardRecord_succeeds() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // exercises the "*." strip branch and bare record name (no _acme-challenge prefix)
        String recordId = provider.addTxtRecord("*.example.com", "digest");
        assertThat(recordId).contains("example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_singleLabelRecord_succeeds() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // single-label exercises both the parts.length<2 branch in extractDomain
        // and the extractHost fallback to "_acme-challenge"
        String recordId = provider.addTxtRecord("localhost", "digest");
        assertThat(recordId).contains("localhost");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_existingValueAtTheName_putsBothValues() throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "[{\"data\":\"apex-digest\",\"name\":\"_acme-challenge\",\"ttl\":600,"
                        + "\"type\":\"TXT\"}]"))
                .thenReturn(response(200, ""));

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "wildcard-digest");

        assertThat(recordId).isEqualTo("_acme-challenge:example.com:wildcard-digest");
        HttpRequest put = request.getAllValues().get(1);
        assertThat(put.method()).isEqualTo("PUT");
        assertThat(JsonMapper.builderWithJackson2Defaults().build().readTree(HttpRequestBodies.bodyOf(put))
                .findValues("data").stream().map(JsonNode::asString).toList()).containsExactly("apex-digest", "wildcard-digest");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_otherValueAtTheName_putsItBack() throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "[{\"data\":\"apex-digest\",\"ttl\":600},{\"data\":\"wildcard-digest\","
                        + "\"ttl\":600}]"))
                .thenReturn(response(200, ""));

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com:apex-digest");

        HttpRequest put = request.getAllValues().get(1);
        assertThat(put.method()).isEqualTo("PUT");
        assertThat(JsonMapper.builderWithJackson2Defaults().build().readTree(HttpRequestBodies.bodyOf(put))
                .findValues("data").stream().map(JsonNode::asString).toList()).containsExactly("wildcard-digest");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_lastValue_deletesTheName() throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "[{\"data\":\"digest\",\"ttl\":600}]"))
                .thenReturn(response(204, ""));

        provider.deleteTxtRecord("_acme-challenge.example.com", "_acme-challenge:example.com:digest");

        assertThat(request.getAllValues()).extracting(HttpRequest::method).containsExactly("GET", "DELETE");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_valueNotThere_changesNothing() throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response(200, "[{\"data\":\"someone-else\",\"ttl\":600}]"));

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
    void addRecord_cname_putsUnderTheCnameRecordPath() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);

        provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example");

        assertThat(request.getValue().uri().getPath()).endsWith("/domains/example.com/records/CNAME/_0a1b");
        JsonNode record = JsonMapper.builderWithJackson2Defaults().build()
                .readTree(HttpRequestBodies.bodyOf(request.getValue())).get(0);
        assertThat(record.path("type").asString()).isEqualTo("CNAME");
        assertThat(record.path("data").asString()).isEqualTo("aa.bb.dcv.example");
    }
}
