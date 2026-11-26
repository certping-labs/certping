// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

import com.certping.agent.scep.ChallengeValidationException;
import com.certping.agent.scep.IntuneUnavailableException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IntuneScepClientTest {

    private final RestTemplate rest = mock(RestTemplate.class);
    private final IntuneScepClient client = new IntuneScepClient(rest);

    @Test
    void acquireTokenReturnsAccessToken() {
        stubPost("https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
                Map.of("access_token", "abc"));

        assertThat(client.acquireToken("tenant", "id", "secret", IntuneScepClient.MANAGE_SCOPE))
                .isEqualTo("abc");
    }

    @Test
    void acquireTokenWithoutAccessTokenIsUnavailable() {
        stubPost("https://login.microsoftonline.com/tenant/oauth2/v2.0/token", Map.of());

        assertThatThrownBy(() -> client.acquireToken("tenant", "id", "secret", IntuneScepClient.MANAGE_SCOPE))
                .isInstanceOf(IntuneUnavailableException.class);
    }

    @Test
    void tokenTransportFailureIsUnavailable() {
        when(rest.exchange(contains("/oauth2/v2.0/token"), eq(HttpMethod.POST),
                any(HttpEntity.class), eq(Map.class)))
                .thenThrow(new ResourceAccessException("connection refused"));

        assertThatThrownBy(() -> client.acquireToken("tenant", "id", "secret", IntuneScepClient.GRAPH_SCOPE))
                .isInstanceOf(IntuneUnavailableException.class);
    }

    @Test
    void discoveryReturnsMatchingServiceUrl() {
        stubGet(Map.of("value", List.of(
                Map.of("providerName", "SomethingElse", "uri", "https://wrong"),
                Map.of("providerName", "ScepRequestValidationFEService", "uri", "https://scep.intune"))));

        assertThat(client.discoverValidationServiceUrl("graph-token")).isEqualTo("https://scep.intune");
    }

    @Test
    void discoveryWithoutTheServiceIsUnavailable() {
        stubGet(Map.of("value", List.of(Map.of("providerName", "SomethingElse", "uri", "https://wrong"))));

        assertThatThrownBy(() -> client.discoverValidationServiceUrl("graph-token"))
                .isInstanceOf(IntuneUnavailableException.class);
    }

    @Test
    void validateAcceptsSuccessCode() {
        stubPost("https://scep.intune/ScepActions/validateRequest", Map.of("code", "Success"));

        assertThatCode(() -> client.validateRequest("https://scep.intune", "token", "txn", "csr", "caller"))
                .doesNotThrowAnyException();
    }

    @Test
    void validateSendsTheApiVersionHeader() {
        stubPost("https://scep.intune/ScepActions/validateRequest", Map.of("code", "Success"));

        client.validateRequest("https://scep.intune", "token", "txn", "csr", "caller");

        org.mockito.ArgumentCaptor<HttpEntity> captor = org.mockito.ArgumentCaptor.forClass(HttpEntity.class);
        verify(rest).exchange(eq("https://scep.intune/ScepActions/validateRequest"),
                eq(HttpMethod.POST), captor.capture(), eq(Map.class));
        assertThat(captor.getValue().getHeaders().getFirst("api-version")).isEqualTo("2018-02-20");
    }

    @Test
    void validateRejectionIsChallengeValidation() {
        stubPost("https://scep.intune/ScepActions/validateRequest",
                Map.of("code", "ChallengeDecryptionError"));

        assertThatThrownBy(() -> client.validateRequest("https://scep.intune", "token", "txn", "csr", "caller"))
                .isInstanceOf(ChallengeValidationException.class);
    }

    @Test
    void validateTransportFailureIsUnavailable() {
        when(rest.exchange(contains("/ScepActions/validateRequest"), eq(HttpMethod.POST),
                any(HttpEntity.class), eq(Map.class)))
                .thenThrow(new ResourceAccessException("timeout"));

        assertThatThrownBy(() -> client.validateRequest("https://scep.intune", "token", "txn", "csr", "caller"))
                .isInstanceOf(IntuneUnavailableException.class);
    }

    @Test
    void successNotificationBadCodeIsUnavailableNotChallengeRejection() {
        stubPost("https://scep.intune/ScepActions/successNotification", Map.of("code", "ServiceError"));

        assertThatThrownBy(() -> client.sendSuccessNotification("https://scep.intune/", "token",
                "txn", "csr", "thumb", "serial", "2026-08-27T00:00:00.000Z", "issuer", "caConfig", "ca", "caller"))
                .isInstanceOf(IntuneUnavailableException.class);
    }

    private void stubPost(String url, Map<String, Object> body) {
        when(rest.exchange(eq(url), eq(HttpMethod.POST), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(response(body));
    }

    private void stubGet(Map<String, Object> body) {
        when(rest.exchange(any(String.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(response(body));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static ResponseEntity<Map> response(Map<String, Object> body) {
        return (ResponseEntity) ResponseEntity.ok(body);
    }
}
