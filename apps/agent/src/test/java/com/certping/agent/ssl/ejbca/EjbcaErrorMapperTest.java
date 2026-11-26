// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiPredicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The classification matters operationally: Permanent dead-letters the message, Transient
 * abandons it for redelivery, and Retryable re-schedules it with a backoff. Getting the branch
 * wrong either loses a certificate that would have succeeded or retries one that never will.
 */
@DisplayName("EjbcaErrorMapper")
class EjbcaErrorMapperTest {

    @Test
    @DisplayName("passes 2xx through")
    void successPassesThrough() {
        assertThatCode(() -> EjbcaErrorMapper.assertSuccess(response(201, "{}"), "op"))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest(name = "HTTP {0} is retryable, not dead-lettered")
    @ValueSource(ints = {429, 503, 408})
    @DisplayName("throttling and timeouts are retryable")
    void throttlingIsRetryable(int status) {
        // A fleet enrolling at once trips EJBCA's limiter or a proxy in front of it; dead-lettering
        // would lose certificates that succeed seconds later.
        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response(status, "slow down"), "op"))
                .isInstanceOf(RetryableAgentException.class)
                .hasMessageContaining("throttled");
    }

    @Test
    @DisplayName("honours Retry-After when the CA supplies one")
    void honoursRetryAfter() {
        HttpResponse<String> response = response(429, "slow down", Map.of("retry-after", "30"));

        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response, "op"))
                .isInstanceOfSatisfying(RetryableAgentException.class, e ->
                        assertThat(e.getRetryAfter()).isEqualTo(Duration.ofSeconds(30)));
    }

    @Test
    @DisplayName("identifies a disabled REST protocol from EJBCA's HTML body")
    void restDisabledIsIdentified() {
        String html = "<html><body>This service has been disabled.</body></html>";

        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response(403, html), "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_REST_DISABLED"));
    }

    @Test
    @DisplayName("does not blame the REST protocol for an unrelated 403")
    void unrelatedHtml403IsNotRestDisabled() {
        // A WAF in front of EJBCA returns its own HTML 403. Sending the operator to re-enable a
        // CA setting that was never off wastes their time.
        String wafPage = "<html><body>Forbidden by security policy</body></html>";

        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response(403, wafPage), "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isNotEqualTo("EJBCA_REST_DISABLED"));
    }

    @Test
    @DisplayName("does not blame the REST protocol for an empty-bodied 403")
    void emptyBody403IsNotRestDisabled() {
        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response(403, ""), "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isNotEqualTo("EJBCA_REST_DISABLED"));
    }

    @Test
    @DisplayName("distinguishes a rejected OAuth token from a missing client certificate")
    void authFailuresAreDistinguished() {
        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(
                response(403, "{\"message\":\"Authentication failed using OAuth Bearer Token\"}"), "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_OAUTH_REJECTED"));

        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(
                response(403, "{\"message\":\"no client certificate or OAuth token received\"}"), "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_CREDENTIAL_NOT_PRESENTED"));
    }

    @Test
    @DisplayName("treats a profile violation as permanent and preserves EJBCA's wording")
    void profileViolationIsPermanent() {
        String body = "{\"error_code\":400,\"error_message\":\"Subject DN field 'COMMONNAME' must exist.\"}";

        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response(400, body), "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e -> {
                    assertThat(e.getErrorCode()).isEqualTo("EJBCA_REQUEST_REJECTED");
                    assertThat(e.getMessage()).contains("COMMONNAME");
                });
    }

    @ParameterizedTest(name = "HTTP {0} is reported as a redirect, not followed")
    @ValueSource(ints = {301, 302, 303, 307, 308})
    @DisplayName("surfaces redirects rather than following them")
    void redirectsAreSurfaced(int status) {
        // A followed redirect would drop the POST body and look like an empty request.
        HttpResponse<String> response =
                response(status, "", Map.of("location", "https://ejbca:8443/x"));

        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response, "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_UNEXPECTED_REDIRECT"));
    }

    @Test
    @DisplayName("treats a server error as transient")
    void serverErrorIsTransient() {
        assertThatThrownBy(() -> EjbcaErrorMapper.assertSuccess(response(500, "boom"), "op"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    @DisplayName("bounds an oversized error body so it cannot flood the logs")
    void oversizedBodyIsTruncated() {
        assertThatThrownBy(() ->
                EjbcaErrorMapper.assertSuccess(response(400, "x".repeat(50_000)), "op"))
                .isInstanceOfSatisfying(PermanentAgentException.class, e -> {
                    assertThat(e.getMessage()).contains("truncated");
                    assertThat(e.getMessage().length()).isLessThan(5_000);
                });
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static HttpResponse<String> response(int status, String body) {
        return response(status, body, Map.of());
    }

    private static HttpResponse<String> response(int status, String body, Map<String, String> headers) {
        BiPredicate<String, String> keepAll = (k, v) -> true;
        HttpHeaders httpHeaders = HttpHeaders.of(
                headers.entrySet().stream().collect(java.util.stream.Collectors.toMap(
                        Map.Entry::getKey, e -> List.of(e.getValue()))), keepAll);

        return new HttpResponse<>() {
            @Override public int statusCode() { return status; }
            @Override public java.net.http.HttpRequest request() { return null; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return httpHeaders; }
            @Override public String body() { return body; }
            @Override public Optional<javax.net.ssl.SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return URI.create("https://ejbca.example.com"); }
            @Override public java.net.http.HttpClient.Version version() {
                return java.net.http.HttpClient.Version.HTTP_1_1;
            }
        };
    }
}
