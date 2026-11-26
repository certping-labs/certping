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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class NameDotComDnsProviderTest {

    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockResponse;

    private NameDotComDnsProvider provider;

    @BeforeEach
    void setUp() {
        provider = new NameDotComDnsProvider("testuser", "test-api-token");
        ReflectionTestUtils.setField(provider, "httpClient", mockHttpClient);
    }

    // ── constructor validation ─────────────────────────────────────────────────

    @Test
    void constructor_blankUsername_throwsPermanentException() {
        assertThatThrownBy(() -> new NameDotComDnsProvider("", "token"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void constructor_blankToken_throwsPermanentException() {
        assertThatThrownBy(() -> new NameDotComDnsProvider("user", "  "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── addTxtRecord ──────────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_success_returnsRecordId() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("{\"id\": 12345, \"host\": \"_acme-challenge\", \"type\": \"TXT\"}");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        String recordId = provider.addTxtRecord("_acme-challenge.example.com", "digest");

        assertThat(recordId).isEqualTo("12345");
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
    void addTxtRecord_serverError_throwsRetryable() throws Exception {
        // 503 ServiceUnavailable is now treated as a throttle/back-off signal — the adapter
        // short-circuits to RetryableAgentException("DNS_PROVIDER_THROTTLED") before reading
        // the body, so the listener re-enqueues through the gateway with a scheduled delay instead
        // of abandon()-ing for immediate redelivery (which was the old TransientAgentException
        // behavior). The adapter inspects headers() for Retry-After even on the 503 path, so
        // we stub an empty HttpHeaders to avoid a NullPointerException — Name.com itself
        // doesn't document a Retry-After, so absent → blind backoff at the listener.
        when(mockResponse.statusCode()).thenReturn(503);
        when(mockResponse.headers()).thenReturn(
                java.net.http.HttpHeaders.of(java.util.Map.of(), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_THROTTLED"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_networkException_throwsTransientException() throws Exception {
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.io.IOException("Network failure"));

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class);
    }

    // ── deleteTxtRecord ───────────────────────────────────────────────────────

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_success_doesNotThrow() throws Exception {
        when(mockResponse.statusCode()).thenReturn(204);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        provider.deleteTxtRecord("_acme-challenge.example.com", "12345");
    }

    @Test
    void deleteTxtRecord_nullRecordId_skipsRequest() {
        provider.deleteTxtRecord("_acme-challenge.example.com", null);
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    void deleteTxtRecord_blankRecordId_skipsRequest() {
        provider.deleteTxtRecord("_acme-challenge.example.com", "   ");
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_networkException_doesNotThrow() throws Exception {
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.io.IOException("Network failure"));

        // Should not throw — deletion is best-effort
        provider.deleteTxtRecord("_acme-challenge.example.com", "12345");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_httpError_logsButDoesNotThrow() throws Exception {
        when(mockResponse.statusCode()).thenReturn(404);
        when(mockResponse.body()).thenReturn("Not found");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // Should not throw
        provider.deleteTxtRecord("_acme-challenge.example.com", "12345");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_rateLimited429WithRetryAfter_preservesIt() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockResponse.headers()).thenReturn(java.net.http.HttpHeaders.of(
                java.util.Map.of("Retry-After", java.util.List.of("75")), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getRetryAfter())
                        .isEqualTo(java.time.Duration.ofSeconds(75)));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_throttledWithMalformedRetryAfter_nullRetryAfter() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockResponse.headers()).thenReturn(java.net.http.HttpHeaders.of(
                java.util.Map.of("Retry-After", java.util.List.of("nope")), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getRetryAfter()).isNull());
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_genericServerError_throwsTransient() throws Exception {
        when(mockResponse.statusCode()).thenReturn(500);
        when(mockResponse.body()).thenReturn("Server Error");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.addTxtRecord("_acme-challenge.example.com", "val"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_ERROR"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_wildcardRecord_succeeds() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("{\"id\": 99}");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // Exercises the *. strip branch in extractDomainName
        assertThat(provider.addTxtRecord("*.example.com", "digest")).isEqualTo("99");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_singleLabelRecord_succeeds() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("{\"id\": 1}");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // single-label exercises parts.length<2 fallback in extractDomainName
        assertThat(provider.addTxtRecord("localhost", "digest")).isEqualTo("1");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_rateLimited_throwsRetryable() throws Exception {
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockResponse.headers()).thenReturn(java.net.http.HttpHeaders.of(
                java.util.Map.of("Retry-After", java.util.List.of("10")), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.deleteTxtRecord("_acme-challenge.example.com", "12345"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> {
                    RetryableAgentException r = (RetryableAgentException) e;
                    assertThat(r.getErrorCode()).isEqualTo("DNS_PROVIDER_THROTTLED");
                    assertThat(r.getRetryAfter()).isEqualTo(java.time.Duration.ofSeconds(10));
                });
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_serviceUnavailable_throwsRetryable() throws Exception {
        when(mockResponse.statusCode()).thenReturn(503);
        when(mockResponse.headers()).thenReturn(java.net.http.HttpHeaders.of(
                java.util.Map.of(), (k, v) -> true));
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        assertThatThrownBy(() -> provider.deleteTxtRecord("_acme-challenge.example.com", "12345"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteTxtRecord_success200_doesNotThrow() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        // 200 OK is also valid for delete (besides 204)
        provider.deleteTxtRecord("_acme-challenge.example.com", "12345");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addTxtRecord_subdomainChallenge_isWrittenAtTheSubdomainHost() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("{\"id\": 7}");
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);

        provider.addTxtRecord("_acme-challenge.api.example.com", "digest");

        JsonNode body = JsonMapper.builderWithJackson2Defaults().build()
                .readTree(HttpRequestBodies.bodyOf(request.getValue()));
        assertThat(body.path("host").asString()).isEqualTo("_acme-challenge.api");
        assertThat(request.getValue().uri().getPath()).endsWith("/domains/example.com/records");
    }

    @Test
    @SuppressWarnings("unchecked")
    void addRecord_cname_sendsTheCnameTypeAndTarget() throws Exception {
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn("{\"id\": 8}");
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        when(mockHttpClient.send(request.capture(), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);

        assertThat(provider.addRecord(DnsRecordType.CNAME, "_0a1b.example.com", "aa.bb.dcv.example")).isEqualTo("8");

        JsonNode body = JsonMapper.builderWithJackson2Defaults().build()
                .readTree(HttpRequestBodies.bodyOf(request.getValue()));
        assertThat(body.path("type").asString()).isEqualTo("CNAME");
        assertThat(body.path("host").asString()).isEqualTo("_0a1b");
        assertThat(body.path("answer").asString()).isEqualTo("aa.bb.dcv.example");
    }
}
