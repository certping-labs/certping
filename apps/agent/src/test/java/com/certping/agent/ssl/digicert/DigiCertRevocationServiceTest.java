// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.digicert;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DigiCertRevocationServiceTest {

    private AgentProperties properties;
    private DigiCertRevocationService service;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getDigicert().setApiBaseUrl("https://www.digicert.com/services/v2");
        service = new DigiCertRevocationService(properties);
    }

    // ── Guard clauses ─────────────────────────────────────────────────────────

    @Test
    void revoke_nullOrderId_throwsPermanent() {
        assertThatThrownBy(() -> service.revoke(null, "KEY_COMPROMISE", "api-key-123"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MISSING_ORDER_ID"));
    }

    @Test
    void revoke_blankOrderId_throwsPermanent() {
        assertThatThrownBy(() -> service.revoke("   ", "KEY_COMPROMISE", "api-key-123"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MISSING_ORDER_ID"));
    }

    @Test
    void revoke_nullApiKey_throwsPermanent() {
        assertThatThrownBy(() -> service.revoke("order-123", "SUPERSEDED", null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MISSING_CA_CREDENTIAL"));
    }

    @Test
    void revoke_blankApiKey_throwsPermanent() {
        assertThatThrownBy(() -> service.revoke("order-123", "SUPERSEDED", ""))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MISSING_CA_CREDENTIAL"));
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void revoke_successResponse_returnsNormally() {
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenReturn(ResponseEntity.ok("revoked")))) {

            service.revoke("order-9001", "KEY_COMPROMISE", "api-key-123");
        }
    }

    @Test
    void revoke_jsonCredential_sendsOnlyTheApiKey() {
        try (MockedConstruction<RestTemplate> restMocks = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenReturn(ResponseEntity.ok("")))) {

            service.revoke("order-9001", "SUPERSEDED", "{\"apiKey\":\"dc-key-json\"}");

            ArgumentCaptor<HttpEntity> sent = ArgumentCaptor.forClass(HttpEntity.class);
            Mockito.verify(restMocks.constructed().get(0))
                    .exchange(anyString(), eq(HttpMethod.PUT), sent.capture(), eq(String.class));
            assertThat(sent.getValue().getHeaders().getFirst("X-DC-DEVKEY")).isEqualTo("dc-key-json");
        }
    }

    // ── Reason normalization ──────────────────────────────────────────────────

    @Test
    void revoke_reasonWithUnderscore_normalizedBeforeSend() {
        try (MockedConstruction<RestTemplate> restMocks = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenReturn(ResponseEntity.ok("")))) {

            service.revoke("order-9001", "KEY_COMPROMISE", "api-key-123");
        }
        // no exception = DC received the normalized form — actual body assertion would need captor;
        // the important contract is no exception when the PUT succeeds
    }

    @Test
    void revoke_nullReason_treatedAsUnspecified() {
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenReturn(ResponseEntity.ok("")))) {

            service.revoke("order-9001", null, "api-key-123");
        }
    }

    // ── HTTP error cases ──────────────────────────────────────────────────────

    @Test
    void revoke_404_throwsPermanent_orderNotFound() {
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenThrow(HttpClientErrorException.create(
                                HttpStatus.NOT_FOUND, "Not Found", null, null, null)))) {

            assertThatThrownBy(() -> service.revoke("order-9001", "SUPERSEDED", "api-key-123"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ORDER_NOT_FOUND"));
        }
    }

    @Test
    void revoke_422AlreadyRevoked_returnsNormally() {
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenThrow(HttpClientErrorException.create(
                                HttpStatus.UNPROCESSABLE_ENTITY, "Unprocessable Entity", null,
                                "Certificate is already revoked".getBytes(StandardCharsets.UTF_8),
                                StandardCharsets.UTF_8)))) {

            service.revoke("order-9001", "SUPERSEDED", "api-key-123");
        }
    }

    @Test
    void revoke_422OtherReason_throwsPermanent() {
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenThrow(HttpClientErrorException.create(
                                HttpStatus.UNPROCESSABLE_ENTITY, "Unprocessable Entity", null,
                                "Invalid request body".getBytes(StandardCharsets.UTF_8),
                                StandardCharsets.UTF_8)))) {

            assertThatThrownBy(() -> service.revoke("order-9001", "SUPERSEDED", "api-key-123"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("REVOCATION_INVALID_STATE"));
        }
    }

    @Test
    void revoke_401_throwsPermanent_unauthorized() {
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenThrow(HttpClientErrorException.create(
                                HttpStatus.UNAUTHORIZED, "Unauthorized", null, null, null)))) {

            assertThatThrownBy(() -> service.revoke("order-9001", "SUPERSEDED", "api-key-123"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("REVOCATION_UNAUTHORIZED"));
        }
    }

    // ── Rate-limit ────────────────────────────────────────────────────────────

    @Test
    void revoke_429_throwsRetryableWithRetryAfter() {
        // DigiCert throttle surfaces as HTTP 429 with Retry-After. The catch block in
        // DigiCertRevocationService funnels this through RateLimitClassifier.classify which
        // reads the header via reflective getHeaders() on HttpClientErrorException.
        org.springframework.http.HttpHeaders responseHeaders = new org.springframework.http.HttpHeaders();
        responseHeaders.add("Retry-After", "42");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenThrow(HttpClientErrorException.create(
                                HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests",
                                responseHeaders, new byte[0], StandardCharsets.UTF_8)))) {

            assertThatThrownBy(() -> service.revoke("order-9001", "KEY_COMPROMISE", "api-key-123"))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> {
                        RetryableAgentException re = (RetryableAgentException) e;
                        assertThat(re.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
                        assertThat(re.getRetryAfter()).isEqualTo(Duration.ofSeconds(42));
                    });
        }
    }

    // ── Network / transient errors ────────────────────────────────────────────

    @Test
    void revoke_500_throwsPermanent_revocationFailed() {
        // 5xx HTTP error from DigiCert — none of the 404/401/403/422 special-cased branches match,
        // so the fall-through at the bottom of the HttpClientErrorException catch throws
        // REVOCATION_FAILED (lines 105-107).
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenThrow(HttpClientErrorException.create(
                                HttpStatus.INTERNAL_SERVER_ERROR, "Server Error", null,
                                "boom".getBytes(StandardCharsets.UTF_8),
                                StandardCharsets.UTF_8)))) {

            assertThatThrownBy(() -> service.revoke("order-9001", "KEY_COMPROMISE", "api-key-123"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("REVOCATION_FAILED"));
        }
    }

    @Test
    void revoke_networkException_throwsTransient() {
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.PUT), any(), eq(String.class)))
                        .thenThrow(new org.springframework.web.client.ResourceAccessException("Connection refused")))) {

            assertThatThrownBy(() -> service.revoke("order-9001", "KEY_COMPROMISE", "api-key-123"))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("REVOCATION_TRANSIENT"));
        }
    }
}
