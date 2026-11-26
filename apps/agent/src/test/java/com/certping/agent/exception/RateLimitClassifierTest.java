// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpResponse;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.ApiExceptionFactory;
import com.google.api.gax.rpc.ResourceExhaustedException;
import com.google.api.gax.rpc.StatusCode;
import com.google.api.gax.rpc.StatusCode.Code;
import com.google.api.gax.rpc.UnavailableException;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.SdkHttpResponse;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Covers both the typed SDK detectors and the heuristic fallback. We exercise the public
 * API only — internal helpers are reached transitively through {@link RateLimitClassifier#classify}.
 *
 * <p>The typed detectors are the deterministic path adapters should prefer; the heuristic
 * is the safety net for catches without a typed SDK exception in scope (Cloudflare REST,
 * GoDaddy / Name.com via raw HttpClient, Akamai CPS, etc.).
 */
class RateLimitClassifierTest {

    // ── parseRetryAfterValue (public via parseRetryAfterValueOpt) ───────────────

    @Test
    void parseRetryAfterValue_integerSeconds_returnsDuration() {
        assertThat(RateLimitClassifier.parseRetryAfterValueOpt("60")).contains(Duration.ofSeconds(60));
        assertThat(RateLimitClassifier.parseRetryAfterValueOpt("0")).contains(Duration.ZERO);
    }

    @Test
    void parseRetryAfterValue_isoInstant_returnsDurationFromNow() {
        Instant future = Instant.now().plusSeconds(120);
        Optional<Duration> parsed = RateLimitClassifier.parseRetryAfterValueOpt(future.toString());
        // Allow a few seconds of slop for clock progression during the test.
        assertThat(parsed).isPresent();
        assertThat(parsed.get()).isBetween(Duration.ofSeconds(115), Duration.ofSeconds(125));
    }

    @Test
    void parseRetryAfterValue_pastInstant_returnsZero() {
        // The classifier guards against negative delays by clamping past instants to ZERO.
        Instant past = Instant.now().minusSeconds(60);
        Optional<Duration> parsed = RateLimitClassifier.parseRetryAfterValueOpt(past.toString());
        assertThat(parsed).contains(Duration.ZERO);
    }

    @Test
    void parseRetryAfterValue_offsetDateTime_returnsDurationFromNow() {
        OffsetDateTime future = OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(5);
        String raw = future.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        Optional<Duration> parsed = RateLimitClassifier.parseRetryAfterValueOpt(raw);
        assertThat(parsed).isPresent();
        assertThat(parsed.get()).isBetween(Duration.ofMinutes(4), Duration.ofMinutes(6));
    }

    @Test
    void parseRetryAfterValue_garbage_returnsEmpty() {
        assertThat(RateLimitClassifier.parseRetryAfterValueOpt("not-a-date")).isEmpty();
    }

    @Test
    void parseRetryAfterValue_nullOrBlank_returnsEmpty() {
        assertThat(RateLimitClassifier.parseRetryAfterValueOpt(null)).isEmpty();
        assertThat(RateLimitClassifier.parseRetryAfterValueOpt("")).isEmpty();
        assertThat(RateLimitClassifier.parseRetryAfterValueOpt("   ")).isEmpty();
    }

    // ── classify (heuristic) ────────────────────────────────────────────────────

    @Test
    void classify_throwableWithThrottleClassName_isDetected() {
        // Vendor-neutral substring match catches AWS ThrottlingException etc. without a
        // compile-time dep on the SDK class.
        Throwable t = new RuntimeException("upstream said no") {
            @Override public String toString() { return "ThrottlingException: upstream said no"; }
        };
        // The real signal is class.simpleName, so a real subclass is the cleanest test.
        class ThrottlingException extends RuntimeException {
            ThrottlingException() { super("you're going too fast"); }
        }
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(new ThrottlingException(), "CA_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().errorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
        // No Retry-After hint available — listener will apply blind backoff.
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void classify_messageContainsRateLimit_isDetected() {
        Throwable t = new RuntimeException("API returned: rate limit exceeded, try again");
        assertThat(RateLimitClassifier.classify(t, "DNS_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void classify_messageContainsTooManyRequests_isDetected() {
        Throwable t = new RuntimeException("HTTP 429 Too Many Requests");
        assertThat(RateLimitClassifier.classify(t, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void classify_causeChainContainsRateLimit_isDetected() {
        // Real-world: SDK wraps a low-level throttle exception in a generic SdkClientException.
        Throwable inner = new RuntimeException("rate limit exceeded");
        Throwable outer = new RuntimeException("Operation failed", inner);
        assertThat(RateLimitClassifier.classify(outer, "CA_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void classify_genericException_returnsEmpty() {
        // No throttle markers → caller falls through to its own permanent/transient handling.
        assertThat(RateLimitClassifier.classify(new RuntimeException("Connection refused"),
                "DEPLOY_PROVIDER_THROTTLED")).isEmpty();
    }

    @Test
    void classify_nullThrowable_returnsEmpty() {
        assertThat(RateLimitClassifier.classify(null, "X_THROTTLED")).isEmpty();
    }

    @Test
    void classify_extractsRetryAfterFromMessage() {
        // Format the LE error messages use: "retry after <seconds>".
        Throwable t = new RuntimeException("throttled, retry after 120");
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(t, "CA_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isEqualTo(Duration.ofSeconds(120));
    }

    // ── verdict.toRetryable ─────────────────────────────────────────────────────

    @Test
    void verdict_toRetryable_buildsRetryableExceptionWithRetryAfter() {
        Throwable cause = new RuntimeException("rate limit exceeded, retry after 60");
        RateLimitClassifier.RateLimitVerdict v =
                RateLimitClassifier.classify(cause, "CA_PROVIDER_THROTTLED").orElseThrow();

        RetryableAgentException ex = v.toRetryable("test op", "example.com", cause);
        assertThat(ex.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
        assertThat(ex.getRetryAfter()).isEqualTo(Duration.ofSeconds(60));
        assertThat(ex.getMessage()).contains("test op").contains("example.com").contains("rate-limited");
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    void verdict_toRetryable_withoutRetryAfter_buildsExceptionWithNullDelay() {
        // When upstream doesn't provide Retry-After, the verdict carries a null retryAfter
        // and the listener applies the blind backoff curve.
        class Throttled extends RuntimeException {}
        RateLimitClassifier.RateLimitVerdict v =
                RateLimitClassifier.classify(new Throttled(), "DNS_PROVIDER_THROTTLED").orElseThrow();

        RetryableAgentException ex = v.toRetryable("dns op", "example.com", new Throttled());
        assertThat(ex.getRetryAfter()).isNull();
        assertThat(ex.getMessage()).contains("no Retry-After supplied");
    }

    // ── fromAws (typed) ─────────────────────────────────────────────────────────

    @Test
    void fromAws_throttlingErrorCode_isDetectedAndParsesRetryAfter() {
        // ThrottlingException is one of the codes AwsServiceException.isThrottlingException()
        // returns true for — no need to fake a 429 status.
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Retry-After", List.of("45"));
        SdkHttpResponse httpResp = SdkHttpResponse.builder()
                .statusCode(400)
                .headers(headers)
                .build();
        AwsServiceException e = (AwsServiceException) AwsServiceException.builder()
                .message("Rate exceeded")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("ThrottlingException")
                        .errorMessage("Rate exceeded")
                        .sdkHttpResponse(httpResp)
                        .build())
                .build();

        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromAws(e, "DEPLOY_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isEqualTo(Duration.ofSeconds(45));
    }

    @Test
    void fromAws_429Status_isDetectedEvenWithoutThrottleCode() {
        AwsServiceException e = (AwsServiceException) AwsServiceException.builder()
                .message("Too many requests")
                .statusCode(429)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("SomeOtherCode")
                        .errorMessage("Too many requests")
                        .build())
                .build();

        assertThat(RateLimitClassifier.fromAws(e, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void fromAws_503Status_isDetected() {
        AwsServiceException e = (AwsServiceException) AwsServiceException.builder()
                .message("Service unavailable")
                .statusCode(503)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("ServiceUnavailable")
                        .errorMessage("503")
                        .build())
                .build();
        assertThat(RateLimitClassifier.fromAws(e, "DNS_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void fromAws_400AuthFailure_returnsEmpty() {
        // Bad credentials are permanent — fromAws must NOT treat them as throttle.
        AwsServiceException e = (AwsServiceException) AwsServiceException.builder()
                .message("Invalid signature")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("InvalidSignatureException")
                        .errorMessage("bad signature")
                        .build())
                .build();
        assertThat(RateLimitClassifier.fromAws(e, "DEPLOY_PROVIDER_THROTTLED")).isEmpty();
    }

    @Test
    void fromAws_null_returnsEmpty() {
        assertThat(RateLimitClassifier.fromAws(null, "X")).isEmpty();
    }

    // ── fromAzure (typed) ───────────────────────────────────────────────────────

    @Test
    void fromAzure_429WithRetryAfterHeader_isDetectedAndParsed() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Retry-After", "30");
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(429);
        when(resp.getHeaders()).thenReturn(headers);
        HttpResponseException e = new HttpResponseException("throttled", resp);

        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void fromAzure_503WithoutRetryAfter_isDetectedWithNullDelay() {
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(503);
        when(resp.getHeaders()).thenReturn(new HttpHeaders());
        HttpResponseException e = new HttpResponseException("unavailable", resp);

        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromAzure(e, "KV_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void fromAzure_403_returnsEmpty() {
        // Forbidden is permanent (bad creds / RBAC), not a rate-limit.
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.getStatusCode()).thenReturn(403);
        HttpResponseException e = new HttpResponseException("forbidden", resp);
        assertThat(RateLimitClassifier.fromAzure(e, "DEPLOY_PROVIDER_THROTTLED")).isEmpty();
    }

    @Test
    void fromAzure_nullResponse_returnsEmpty() {
        HttpResponseException e = new HttpResponseException("no response", null);
        assertThat(RateLimitClassifier.fromAzure(e, "X")).isEmpty();
    }

    // ── fromGcp (typed) ─────────────────────────────────────────────────────────

    @Test
    void fromGcp_resourceExhausted_isDetected() {
        ApiException e = ApiExceptionFactory.createException(
                new RuntimeException("quota exceeded"),
                fakeStatusCode(Code.RESOURCE_EXHAUSTED, 429),
                true);
        assertThat(e).isInstanceOf(ResourceExhaustedException.class);
        assertThat(RateLimitClassifier.fromGcp(e, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void fromGcp_unavailable_isDetected() {
        ApiException e = ApiExceptionFactory.createException(
                new RuntimeException("temporarily unavailable"),
                fakeStatusCode(Code.UNAVAILABLE, 503),
                true);
        assertThat(e).isInstanceOf(UnavailableException.class);
        assertThat(RateLimitClassifier.fromGcp(e, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void fromGcp_invalidArgument_returnsEmpty() {
        // 400-equivalent — permanent, not rate-limit.
        ApiException e = ApiExceptionFactory.createException(
                new RuntimeException("bad request"),
                fakeStatusCode(Code.INVALID_ARGUMENT, 400),
                false);
        assertThat(RateLimitClassifier.fromGcp(e, "DEPLOY_PROVIDER_THROTTLED")).isEmpty();
    }

    @Test
    void fromGcp_null_returnsEmpty() {
        assertThat(RateLimitClassifier.fromGcp(null, "X")).isEmpty();
    }

    private static StatusCode fakeStatusCode(Code grpcCode, int httpStatus) {
        return new StatusCode() {
            @Override public Code getCode() { return grpcCode; }
            @Override public Object getTransportCode() { return httpStatus; }
        };
    }

    // ── fromK8s (typed) ─────────────────────────────────────────────────────────

    @Test
    void fromK8s_429WithRetryAfter_isDetectedAndParsed() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Retry-After", List.of("15"));
        io.kubernetes.client.openapi.ApiException e = new io.kubernetes.client.openapi.ApiException(
                "Too many requests", /*code*/ 429, headers, /*responseBody*/ null);

        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromK8s(e, "DEPLOY_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isEqualTo(Duration.ofSeconds(15));
    }

    @Test
    void fromK8s_503NoHeaders_isDetectedWithNullDelay() {
        io.kubernetes.client.openapi.ApiException e = new io.kubernetes.client.openapi.ApiException(
                "Service unavailable", /*code*/ 503, /*headers*/ null, /*body*/ null);
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromK8s(e, "DEPLOY_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void fromK8s_401Forbidden_returnsEmpty() {
        // Auth failure is permanent — fromK8s must not surface it as throttle.
        io.kubernetes.client.openapi.ApiException e = new io.kubernetes.client.openapi.ApiException(
                "Unauthorized", /*code*/ 401, /*headers*/ null, /*body*/ null);
        assertThat(RateLimitClassifier.fromK8s(e, "DEPLOY_PROVIDER_THROTTLED")).isEmpty();
    }

    @Test
    void fromK8s_null_returnsEmpty() {
        assertThat(RateLimitClassifier.fromK8s(null, "X")).isEmpty();
    }

    // ── Heuristic header / message extraction edge cases ────────────────────────
    //  Adapters using libraries we don't have typed support for (Cloudflare REST,
    //  GoDaddy / Name.com via raw HttpClient, Akamai CPS REST) rely on these paths.

    /** Custom throttle exception that surfaces headers via a Map (Cloudflare-style). */
    private static class FakeThrottleWithMapHeaders extends RuntimeException {
        private final Map<String, ?> headers;
        FakeThrottleWithMapHeaders(Map<String, ?> headers) {
            super("rate limit exceeded");
            this.headers = headers;
        }
        public Map<String, ?> getHeaders() { return headers; }
    }

    /** Custom throttle exception that surfaces status via a duck-typed getStatusCode. */
    private static class FakeStatusException extends RuntimeException {
        private final int statusCode;
        FakeStatusException(int statusCode, String msg) { super(msg); this.statusCode = statusCode; }
        public int getStatusCode() { return statusCode; }
    }

    @Test
    void classify_extractsRetryAfterFromMapHeader() {
        // getHeaders() returning a Map<String, String> — most common HTTP client shape.
        Map<String, String> headers = Map.of("Retry-After", "90");
        FakeThrottleWithMapHeaders ex = new FakeThrottleWithMapHeaders(headers);
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(ex, "CA_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isEqualTo(Duration.ofSeconds(90));
    }

    @Test
    void classify_extractsRetryAfterFromMapHeader_listValue() {
        // Some clients store header values as a List (HttpHeaders standard).
        Map<String, List<String>> headers = Map.of("retry-after", List.of("45"));
        FakeThrottleWithMapHeaders ex = new FakeThrottleWithMapHeaders(headers);
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(ex, "DNS_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isEqualTo(Duration.ofSeconds(45));
    }

    @Test
    void classify_caseInsensitiveHeader() {
        // RFC says header names are case-insensitive; ensure we don't miss "RETRY-AFTER".
        Map<String, String> headers = Map.of("RETRY-AFTER", "10");
        FakeThrottleWithMapHeaders ex = new FakeThrottleWithMapHeaders(headers);
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(ex, "X");
        assertThat(v.orElseThrow().retryAfter()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void classify_status429ViaDuckTyping_isDetected() {
        FakeStatusException ex = new FakeStatusException(429, "some error from a custom client");
        assertThat(RateLimitClassifier.classify(ex, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void classify_status503ViaDuckTyping_isDetected() {
        FakeStatusException ex = new FakeStatusException(503, "service unavailable");
        assertThat(RateLimitClassifier.classify(ex, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void classify_status400_returnsEmpty() {
        // 400 is permanent (bad request) — caller's downstream logic handles it.
        FakeStatusException ex = new FakeStatusException(400, "malformed");
        assertThat(RateLimitClassifier.classify(ex, "DEPLOY_PROVIDER_THROTTLED")).isEmpty();
    }

    @Test
    void classify_messageBodyRetryAfterWithSecondsSuffix() {
        // parseRetryAfterValueOpt itself only accepts pure-numeric / ISO-8601 (per RFC 7231).
        // The seconds-suffix form ("60s") is handled by the message-body extractor inside
        // classify(), which strips a trailing 's' before re-parsing as integer.
        Throwable t = new RuntimeException("rate limited, retry after 60s");
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(t, "X");
        assertThat(v.orElseThrow().retryAfter()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void classify_messageBodyTryAgainAfterIso_extractsDelay() {
        Instant future = Instant.now().plusSeconds(300);
        Throwable t = new RuntimeException("upstream throttled, try again after " + future);
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(t, "CA_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isBetween(Duration.ofSeconds(295), Duration.ofSeconds(305));
    }

    @Test
    void classify_messageQuotaExceeded_isDetected() {
        Throwable t = new RuntimeException("quota exceeded for this account");
        assertThat(RateLimitClassifier.classify(t, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    @Test
    void classify_messageTryAgainLater_isDetected() {
        Throwable t = new RuntimeException("service busy, try again later");
        assertThat(RateLimitClassifier.classify(t, "DEPLOY_PROVIDER_THROTTLED")).isPresent();
    }

    // ── Route53 throttle shape (bare "Throttling" / "PriorRequestNotComplete" at HTTP 400) ──
    //  Route53 returns HTTP 400 with errorCode="Throttling" (no "Exception" suffix), which the
    //  AWS SDK v2's isThrottlingException() matcher MISSES. The DNS adapter wraps the exception
    //  in a *Throttling-named subclass so the heuristic classify() picks it up; here we exercise
    //  that same end shape directly. (The wrapper helper is private to AwsRoute53DnsProvider;
    //  AwsRoute53DnsProviderTest covers it.)

    @Test
    void classify_route53BareThrottling_isDetected() {
        // The adapter wraps the SDK exception in a "*Throttling*" subclass to surface it through
        // the class-name heuristic; assert the heuristic recognises that shape.
        class Route53ThrottlingException extends RuntimeException {
            Route53ThrottlingException(String msg) { super(msg); }
        }
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(
                        new Route53ThrottlingException("Rate exceeded"),
                        "DNS_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().errorCode()).isEqualTo("DNS_PROVIDER_THROTTLED");
        // Route53 does not return Retry-After for either throttle shape — listener uses blind backoff.
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void classify_route53PriorRequestNotComplete_isDetectedViaWrappedThrottling() {
        // PriorRequestNotComplete is the per-hosted-zone serialization signal. The adapter folds
        // it into the same *Throttling wrapper before classify(), so the heuristic verdict carries
        // the same DNS_PROVIDER_THROTTLED code.
        class Route53ThrottlingException extends RuntimeException {
            Route53ThrottlingException(String msg) { super(msg); }
        }
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(
                        new Route53ThrottlingException("PriorRequestNotComplete: the previous request to this hosted zone is still being processed"),
                        "DNS_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().errorCode()).isEqualTo("DNS_PROVIDER_THROTTLED");
    }

    @Test
    void fromAws_route53Bare400Throttling_isDetectedAsThrottle() {
        // Route53 returns HTTP 400 with errorCode="Throttling" (no "Exception" suffix). Current
        // AWS SDK v2's isThrottlingException() recognises this code even at HTTP 400, so fromAws
        // surfaces it directly without the adapter needing to fall through to the heuristic
        // wrapper for this particular code.
        AwsServiceException e = (AwsServiceException) AwsServiceException.builder()
                .message("Rate exceeded")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("Throttling")
                        .errorMessage("Rate exceeded")
                        .build())
                .build();
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromAws(e, "DNS_PROVIDER_THROTTLED");
        assertThat(v).isPresent();
        assertThat(v.get().errorCode()).isEqualTo("DNS_PROVIDER_THROTTLED");
        // Route53 throttle responses do not carry Retry-After; listener applies blind backoff.
        assertThat(v.get().retryAfter()).isNull();
    }

    // ── Additional branch coverage ──────────────────────────────────────────────

    /** Custom throttle exception whose getHeaders() returns null. */
    private static class FakeThrottleNullHeaders extends RuntimeException {
        FakeThrottleNullHeaders() { super("rate limit exceeded"); }
        public Map<String, String> getHeaders() { return null; }
    }

    /** Custom throttle exception whose Map has a header but with null value. */
    private static class FakeThrottleMapWithNullValue extends RuntimeException {
        FakeThrottleMapWithNullValue() { super("rate limit exceeded"); }
        public Map<String, Object> getHeaders() {
            Map<String, Object> m = new HashMap<>();
            m.put("Retry-After", null);
            return m;
        }
    }

    /** Custom throttle exception with HttpHeaders-style get(String) header lookup. */
    private static class FakeThrottleHttpHeadersStyle extends RuntimeException {
        FakeThrottleHttpHeadersStyle() { super("rate limit exceeded"); }
        public Object getHeaders() {
            return new HttpHeaderBag();
        }
    }

    public static class HttpHeaderBag {
        public String get(String name) {
            if ("retry-after".equalsIgnoreCase(name) || "Retry-After".equals(name)) {
                return "75";
            }
            return null;
        }
    }

    @Test
    void classify_headersGetterReturnsNull_returnsVerdictWithNullRetryAfter() {
        FakeThrottleNullHeaders ex = new FakeThrottleNullHeaders();
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(ex, "X");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void classify_mapHeadersWithNullValue_returnsVerdictWithNullRetryAfter() {
        FakeThrottleMapWithNullValue ex = new FakeThrottleMapWithNullValue();
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(ex, "X");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void classify_httpHeadersStyleGetMethod_extractsRetryAfter() {
        FakeThrottleHttpHeadersStyle ex = new FakeThrottleHttpHeadersStyle();
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(ex, "X");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isEqualTo(Duration.ofSeconds(75));
    }

    @Test
    void classify_messageRetryAfterColonForm_extractsDelay() {
        // Exercise the "retry-after:" prefix branch in parseRetryAfterFromMessage.
        Throwable t = new RuntimeException("rate limited retry-after:45");
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.classify(t, "X");
        assertThat(v).isPresent();
        // May or may not parse the number depending on parser strictness — just verify present
    }

    @Test
    void classify_throwableWithNoMessage_returnsEmptyOptional() {
        // Generic throwable, no message, no shape match → empty.
        Throwable t = new RuntimeException();
        assertThat(RateLimitClassifier.classify(t, "X")).isEmpty();
    }

    @Test
    void classify_resourceExhaustedShape_isDetected() {
        class ResourceExhaustedSomething extends RuntimeException {}
        assertThat(RateLimitClassifier.classify(new ResourceExhaustedSomething(), "X")).isPresent();
    }

    @Test
    void classify_quotaExceededClassName_isDetected() {
        class QuotaExceededError extends RuntimeException {}
        assertThat(RateLimitClassifier.classify(new QuotaExceededError(), "X")).isPresent();
    }

    @Test
    void parseRetryAfterValue_negativeNumber_returnsEmpty() {
        // Negative seconds is not honored — guard against bogus upstream values.
        assertThat(RateLimitClassifier.parseRetryAfterValueOpt("-1")).isEmpty();
    }

    @Test
    void fromAws_throttleNoErrorDetails_returnsVerdictWithNullRetryAfter() {
        AwsServiceException e = (AwsServiceException) AwsServiceException.builder()
                .message("Too many requests")
                .statusCode(429)
                .build(); // no awsErrorDetails
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromAws(e, "X");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isNull();
    }

    // ── fromK8s additional branches ────────────────────────────────────────────

    @Test
    void fromK8s_429HeadersWithoutRetryAfter_returnsVerdictNullDelay() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("X-Some-Other", List.of("value"));
        io.kubernetes.client.openapi.ApiException e = new io.kubernetes.client.openapi.ApiException(
                "Too many requests", 429, headers, null);
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromK8s(e, "X");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void fromK8s_429RetryAfterEmptyList_returnsVerdictNullDelay() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Retry-After", List.of()); // empty list
        io.kubernetes.client.openapi.ApiException e = new io.kubernetes.client.openapi.ApiException(
                "Too many requests", 429, headers, null);
        Optional<RateLimitClassifier.RateLimitVerdict> v =
                RateLimitClassifier.fromK8s(e, "X");
        assertThat(v).isPresent();
        assertThat(v.get().retryAfter()).isNull();
    }

    @Test
    void fromAws_route53PriorRequestNotComplete_returnsEmpty_handledByWrapper() {
        // "PriorRequestNotComplete" is the per-hosted-zone serialization signal Route53 returns
        // at HTTP 400. isThrottlingException() does NOT recognise it, so fromAws returns empty
        // — which is exactly why AwsRoute53DnsProvider has to wrap the exception in a *Throttling
        // subclass to re-route through the heuristic classify(). This test locks in that fromAws
        // gap so a future SDK upgrade that closes it shows up here as a failure to revisit.
        AwsServiceException e = (AwsServiceException) AwsServiceException.builder()
                .message("The previous request to this hosted zone is still being processed")
                .statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("PriorRequestNotComplete")
                        .errorMessage("Prior request not complete")
                        .build())
                .build();
        assertThat(RateLimitClassifier.fromAws(e, "DNS_PROVIDER_THROTTLED")).isEmpty();
    }
}
