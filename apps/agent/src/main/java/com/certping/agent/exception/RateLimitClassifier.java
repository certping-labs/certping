// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import com.azure.core.exception.HttpResponseException;
import com.google.api.gax.rpc.ResourceExhaustedException;
import com.google.api.gax.rpc.UnavailableException;
import software.amazon.awssdk.awscore.exception.AwsServiceException;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Collection;

/**
 * Central detector for "this upstream is asking us to back off". Each provider SDK throws
 * its own exception shape; rather than every adapter re-implementing the same {@code
 * if (e instanceof X || e.getStatusCode() == 429 || ...)} ladder, we funnel everything
 * through {@link #classify(Throwable, String)} and let the adapter throw
 * {@link RetryableAgentException} on a non-empty result.
 *
 * <p>Detection rules (checked in order, first hit wins):
 * <ul>
 *   <li>Any throwable in the cause chain whose class name hints at throttling
 *       ({@code Throttl*}, {@code TooManyRequests*}, {@code RateLimit*}, {@code Quota*},
 *       {@code ResourceExhausted*}). Vendor-neutral — catches AWS, Azure, GCP, Cloudflare,
 *       Kubernetes client variants without compile-time dependencies on each SDK.</li>
 *   <li>HTTP status 429 or 503 — discovered via duck-typed {@code getStatusCode()} /
 *       {@code statusCode()} / {@code getCode()} reflective lookup so we work with
 *       arbitrary HTTP client libraries.</li>
 *   <li>Message body contains "rate limit", "too many requests", "throttl", "quota exceeded",
 *       "try again later" — last-ditch when the SDK gives us no structured signal.</li>
 * </ul>
 *
 * <p>The returned {@link Duration} is the upstream's hint when one was parseable from
 * (a) a {@code Retry-After} header surfaced via a {@code getHeaders()} reflective lookup,
 * (b) an ISO-8601 / HTTP-date / integer-seconds string we found in the message body, or
 * (c) {@link Optional#empty()} when we know it's rate-limited but don't know for how long
 * (the listener applies the blind backoff curve in that case).
 *
 * <p>Adapters should call this at the top of their catch blocks:
 * <pre>{@code
 * } catch (SomeProviderException e) {
 *     Optional<RateLimitVerdict> rl = RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
 *     if (rl.isPresent()) {
 *         throw rl.get().toRetryable("DigiCert order request", domain, e);
 *     }
 *     // fall through to existing permanent/transient classification
 * }
 * }</pre>
 */
public final class RateLimitClassifier {

    /** Verdict returned when {@link RateLimitClassifier#classify} finds a throttle signal. */
    public static final class RateLimitVerdict {
        private final String errorCode;
        private final Duration retryAfter;

        private RateLimitVerdict(String errorCode, Duration retryAfter) {
            this.errorCode = errorCode;
            this.retryAfter = retryAfter;
        }

        public String errorCode() {
            return errorCode;
        }

        /** {@code null} when upstream didn't tell us how long to wait — caller gets blind backoff. */
        public Duration retryAfter() {
            return retryAfter;
        }

        /** Builds the exception the listener routes through scheduled retry. */
        public RetryableAgentException toRetryable(String operation, String target, Throwable cause) {
            String msg = operation + " for " + target + " was rate-limited"
                    + (retryAfter == null ? " (no Retry-After supplied)"
                                          : " (Retry-After=" + retryAfter + ")");
            return new RetryableAgentException(errorCode, msg, retryAfter, cause);
        }
    }

    private RateLimitClassifier() {}

    // ─────────────────────────────────────────────────────────────────────────────
    //  Typed SDK detectors — these use each SDK's documented throttle / Retry-After
    //  accessors directly (no reflection, no class-name heuristics). Adapters should
    //  prefer the typed variant matching the exception caught at their call site;
    //  the heuristic {@link #classify} below is a fallback for wrapped/non-SDK
    //  throwables.
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * AWS SDK v2: relies on {@link AwsServiceException#isThrottlingException()} (which the SDK
     * already maps from the documented throttle error codes — {@code Throttling},
     * {@code ThrottlingException}, {@code ProvisionedThroughputExceeded}, {@code TooManyRequests*},
     * {@code RequestLimitExceeded}, {@code BandwidthLimitExceeded}, {@code SlowDown}, etc. — plus
     * HTTP {@code 429}). Falls back to a direct {@code 429}/{@code 503} status-code check for
     * services whose throttle code isn't in the SDK's set. Retry-After is read from
     * {@code awsErrorDetails().sdkHttpResponse().firstMatchingHeader("Retry-After")}.
     */
    public static Optional<RateLimitVerdict> fromAws(AwsServiceException e, String defaultErrorCode) {
        if (e == null) {
            return Optional.empty();
        }
        boolean throttled = e.isThrottlingException();
        if (!throttled) {
            int status = e.statusCode();
            if (!ProviderThrottleCodes.UNIVERSAL_THROTTLE_STATUSES.contains(status)) {
                return Optional.empty();
            }
        }
        Duration retryAfter = null;
        if (e.awsErrorDetails() != null && e.awsErrorDetails().sdkHttpResponse() != null) {
            retryAfter = e.awsErrorDetails().sdkHttpResponse()
                    .firstMatchingHeader("Retry-After")
                    .flatMap(RateLimitClassifier::parseRetryAfterValue)
                    .orElse(null);
        }
        return Optional.of(new RateLimitVerdict(defaultErrorCode, retryAfter));
    }

    /**
     * Azure SDK: covers both {@link HttpResponseException} (azure-core) and its
     * {@code ManagementException} subclass (azure-core-management — what ARM clients throw).
     * Inspects the typed {@code HttpResponse} for status {@code 429}/{@code 503} and reads the
     * standard {@code Retry-After} response header.
     */
    public static Optional<RateLimitVerdict> fromAzure(HttpResponseException e, String defaultErrorCode) {
        if (e == null || e.getResponse() == null) {
            return Optional.empty();
        }
        int status = e.getResponse().getStatusCode();
        if (!ProviderThrottleCodes.AZURE_THROTTLE_STATUSES.contains(status)) {
            return Optional.empty();
        }
        Duration retryAfter = null;
        try {
            String raw = e.getResponse().getHeaders().getValue("Retry-After");
            if (raw != null) {
                retryAfter = parseRetryAfterValue(raw).orElse(null);
            }
        } catch (RuntimeException ignored) {
            // Some HttpHeaders implementations don't support the deprecated String overload;
            // leave retryAfter null → listener applies blind backoff.
        }
        return Optional.of(new RateLimitVerdict(defaultErrorCode, retryAfter));
    }

    /**
     * GCP gax: {@link ResourceExhaustedException} maps from the gRPC {@code RESOURCE_EXHAUSTED}
     * status (the rate-limit signal) and {@link UnavailableException} from {@code UNAVAILABLE}
     * (typically transient throttle/maintenance with a sensible retry hint). Both also surface
     * as HTTP {@code 429} / {@code 503} when the call goes through REST transport, so callers
     * who catch the broader {@link com.google.api.gax.rpc.ApiException} fall through to a
     * status-code check.
     *
     * <p>gax exposes a typed {@code RetryInfo} on {@link com.google.api.gax.rpc.ErrorDetails}
     * when the server returned one (carrying {@code retryDelay} seconds + nanos). We read it
     * defensively via the no-args {@code getRetryInfo()} accessor — older gax versions don't
     * have it, in which case we surface a {@code null} retryAfter and the listener applies the
     * blind backoff curve.
     */
    public static Optional<RateLimitVerdict> fromGcp(com.google.api.gax.rpc.ApiException e, String defaultErrorCode) {
        if (e == null) {
            return Optional.empty();
        }
        boolean throttled = e instanceof ResourceExhaustedException || e instanceof UnavailableException;
        if (!throttled) {
            // getStatusCode() returns gax StatusCode; getTransportCode() is Object (HTTP int for
            // HTTP transport, Status.Code enum for gRPC). Only the int form tells us 429/503.
            if (e.getStatusCode() == null) {
                return Optional.empty();
            }
            Object transport = e.getStatusCode().getTransportCode();
            if (!(transport instanceof Number)) {
                return Optional.empty();
            }
            int httpCode = ((Number) transport).intValue();
            if (!ProviderThrottleCodes.GCP_THROTTLE_STATUSES.contains(httpCode)) {
                return Optional.empty();
            }
        }
        Duration retryAfter = extractGcpRetryDelay(e);
        return Optional.of(new RateLimitVerdict(defaultErrorCode, retryAfter));
    }

    private static Duration extractGcpRetryDelay(com.google.api.gax.rpc.ApiException e) {
        try {
            var errorDetails = e.getErrorDetails();
            if (errorDetails == null) {
                return null;
            }
            // RetryInfo is a google.rpc.RetryInfo protobuf — Duration with seconds + nanos.
            // Older gax: ErrorDetails has no getRetryInfo(); newer: returns null when absent.
            var getRetryInfo = errorDetails.getClass().getMethod("getRetryInfo");
            Object retryInfo = getRetryInfo.invoke(errorDetails);
            if (retryInfo == null) {
                return null;
            }
            var getRetryDelay = retryInfo.getClass().getMethod("getRetryDelay");
            Object delay = getRetryDelay.invoke(retryInfo);
            if (delay == null) {
                return null;
            }
            long seconds = ((Number) delay.getClass().getMethod("getSeconds").invoke(delay)).longValue();
            int nanos = ((Number) delay.getClass().getMethod("getNanos").invoke(delay)).intValue();
            return Duration.ofSeconds(seconds, nanos);
        } catch (ReflectiveOperationException ignored) {
            return null;
        }
    }

    /**
     * Kubernetes Java client: {@link io.kubernetes.client.openapi.ApiException#getCode()} is the
     * HTTP status. The K8s API server returns {@code 429 Too Many Requests} with a
     * {@code Retry-After} response header for both apiserver-flowcontrol throttle and admission
     * webhook throttle; we honor both.
     */
    public static Optional<RateLimitVerdict> fromK8s(io.kubernetes.client.openapi.ApiException e, String defaultErrorCode) {
        if (e == null) {
            return Optional.empty();
        }
        int code = e.getCode();
        if (!ProviderThrottleCodes.K8S_THROTTLE_STATUSES.contains(code)) {
            return Optional.empty();
        }
        Duration retryAfter = null;
        Map<String, List<String>> headers = e.getResponseHeaders();
        if (headers != null) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                if (entry.getKey() != null
                        && "retry-after".equalsIgnoreCase(entry.getKey())
                        && entry.getValue() != null
                        && !entry.getValue().isEmpty()) {
                    retryAfter = parseRetryAfterValue(entry.getValue().get(0)).orElse(null);
                    break;
                }
            }
        }
        return Optional.of(new RateLimitVerdict(defaultErrorCode, retryAfter));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  Heuristic fallback — adapters using libraries we don't have typed support
    //  for (Cloudflare REST, F5 BigIP REST, Akamai CPS REST, raw HttpClient against
    //  GoDaddy / Name.com), or anything wrapped in a generic RuntimeException.
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * Returns a verdict when {@code throwable}'s cause chain indicates an upstream throttle/
     * rate-limit. {@code defaultErrorCode} is used as the {@link RetryableAgentException}'s
     * code — pick one of {@code CA_PROVIDER_THROTTLED}, {@code DNS_PROVIDER_THROTTLED},
     * {@code DEPLOY_PROVIDER_THROTTLED}, {@code KV_PROVIDER_THROTTLED} based on the caller's
     * domain so the server can render a specific user-facing message.
     */
    public static Optional<RateLimitVerdict> classify(Throwable throwable, String defaultErrorCode) {
        if (throwable == null) {
            return Optional.empty();
        }
        Throwable cursor = throwable;
        while (cursor != null) {
            if (isRateLimitShape(cursor)) {
                Duration retryAfter = extractRetryAfter(cursor).orElse(null);
                return Optional.of(new RateLimitVerdict(defaultErrorCode, retryAfter));
            }
            cursor = cursor.getCause();
        }
        return Optional.empty();
    }

    private static boolean isRateLimitShape(Throwable t) {
        String className = t.getClass().getSimpleName().toLowerCase(Locale.ROOT);
        if (className.contains("throttl")
                || className.contains("toomanyrequest")
                || className.contains("ratelimit")
                || className.contains("quotaexceeded")
                || className.contains("resourceexhausted")) {
            return true;
        }
        Integer status = extractStatusCode(t);
        if (status != null && ProviderThrottleCodes.UNIVERSAL_THROTTLE_STATUSES.contains(status)) {
            return true;
        }
        String msg = t.getMessage();
        if (msg != null) {
            String lower = msg.toLowerCase(Locale.ROOT);
            if (lower.contains("rate limit")
                    || lower.contains("too many requests")
                    || lower.contains("throttl")
                    || lower.contains("quota exceeded")
                    || lower.contains("try again later")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Reflective probe for the various HTTP-status accessors SDKs expose. We don't take a
     * compile-time dependency on AWS/Azure/GCP/Kubernetes/etc. — each just happens to spell
     * the getter slightly differently.
     */
    private static Integer extractStatusCode(Throwable t) {
        for (String getter : new String[]{"getStatusCode", "statusCode", "getCode", "getHttpStatus", "getHttpStatusCode"}) {
            try {
                var m = t.getClass().getMethod(getter);
                Object v = m.invoke(t);
                if (v instanceof Number n) {
                    return n.intValue();
                }
            } catch (ReflectiveOperationException ignored) {
                // try next
            }
        }
        return null;
    }

    /**
     * Best-effort extraction of upstream's Retry-After hint. Looks at headers (via {@code
     * getHeaders()} / {@code headers()}) and the message body. Returns {@link Optional#empty()}
     * when nothing parseable was found — the listener will apply the blind backoff curve.
     */
    static Optional<Duration> extractRetryAfter(Throwable t) {
        Optional<Duration> fromHeaders = tryHeaderRetryAfter(t);
        if (fromHeaders.isPresent()) {
            return fromHeaders;
        }
        String msg = t.getMessage();
        if (msg != null) {
            return parseRetryAfterFromMessage(msg);
        }
        return Optional.empty();
    }

    private static Optional<Duration> tryHeaderRetryAfter(Throwable t) {
        for (String getter : new String[]{"getHeaders", "headers", "getResponseHeaders"}) {
            try {
                var m = t.getClass().getMethod(getter);
                Object headers = m.invoke(t);
                Optional<String> raw = headerValue(headers, "retry-after");
                if (raw.isPresent()) {
                    Optional<Duration> parsed = parseRetryAfterValue(raw.get());
                    if (parsed.isPresent()) {
                        return parsed;
                    }
                }
            } catch (ReflectiveOperationException ignored) {
                // try next
            }
        }
        return Optional.empty();
    }

    @SuppressWarnings("unchecked")
    private static Optional<String> headerValue(Object headers, String wantedLower) {
        if (headers == null) {
            return Optional.empty();
        }
        // Spring's HttpHeaders stopped being a Map in Framework 7; read it directly.
        if (headers instanceof org.springframework.http.HttpHeaders springHeaders) {
            String first = springHeaders.getFirst("Retry-After");
            return Optional.ofNullable(first);
        }
        // java.util.Map<String, ?> — most HTTP clients normalise headers to a Map.
        if (headers instanceof Map<?, ?> map) {
            for (var entry : map.entrySet()) {
                Object k = entry.getKey();
                if (k != null && wantedLower.equalsIgnoreCase(k.toString())) {
                    Object v = entry.getValue();
                    if (v instanceof Collection<?> coll && !coll.isEmpty()) {
                        return Optional.of(coll.iterator().next().toString());
                    }
                    if (v != null) {
                        return Optional.of(v.toString());
                    }
                }
            }
        }
        // Try a get(String) method (HttpHeaders-style).
        try {
            var get = headers.getClass().getMethod("get", String.class);
            Object v = get.invoke(headers, wantedLower);
            if (v == null) {
                v = get.invoke(headers, "Retry-After");
            }
            if (v instanceof Collection<?> coll && !coll.isEmpty()) {
                return Optional.of(coll.iterator().next().toString());
            }
            if (v != null) {
                return Optional.of(v.toString());
            }
        } catch (ReflectiveOperationException ignored) {
            // not that shape
        }
        return Optional.empty();
    }

    /**
     * Parses a value from a Retry-After header. Per RFC 7231 it can be either an integer
     * (seconds) or an HTTP-date. We also accept ISO-8601 because some SDKs surface it that
     * way after their own normalisation.
     */
    public static Optional<Duration> parseRetryAfterValueOpt(String raw) {
        return parseRetryAfterValue(raw);
    }

    static Optional<Duration> parseRetryAfterValue(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) {
            return Optional.empty();
        }
        // Pure integer = seconds.
        try {
            long seconds = Long.parseLong(trimmed);
            if (seconds >= 0) {
                return Optional.of(Duration.ofSeconds(seconds));
            }
        } catch (NumberFormatException ignored) {
            // fall through
        }
        // ISO-8601 instant.
        try {
            Instant when = Instant.parse(trimmed);
            return Optional.of(durationUntil(when));
        } catch (DateTimeParseException ignored) {
            // fall through
        }
        // ISO offset date-time (LE acme4j surfaces it this way).
        try {
            OffsetDateTime when = OffsetDateTime.parse(trimmed);
            return Optional.of(durationUntil(when.toInstant()));
        } catch (DateTimeParseException ignored) {
            // give up
        }
        return Optional.empty();
    }

    /**
     * Look for a few common patterns inside an SDK's error message: "retry after 1234",
     * "retry-after: 60s", "try again after 2026-06-25T...". Conservative — we'd rather
     * blind-backoff than mis-parse a number.
     */
    static Optional<Duration> parseRetryAfterFromMessage(String message) {
        String lower = message.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf("retry after ");
        if (idx < 0) {
            idx = lower.indexOf("retry-after:");
            if (idx >= 0) {
                idx = idx + "retry-after:".length();
            }
        } else {
            idx = idx + "retry after ".length();
        }
        if (idx < 0) {
            idx = lower.indexOf("try again after ");
            if (idx >= 0) {
                idx = idx + "try again after ".length();
            }
        }
        if (idx < 0 || idx >= lower.length()) {
            return Optional.empty();
        }
        // Trim a trailing word: stop at first whitespace/comma/period that ends a token.
        int end = idx;
        while (end < lower.length() && !Character.isWhitespace(lower.charAt(end))
                && lower.charAt(end) != ',' && lower.charAt(end) != ')') {
            end++;
        }
        String candidate = message.substring(idx, end);
        // strip trailing seconds-unit suffix
        if (candidate.endsWith("s") || candidate.endsWith("S")) {
            try {
                long secs = Long.parseLong(candidate.substring(0, candidate.length() - 1));
                return Optional.of(Duration.ofSeconds(secs));
            } catch (NumberFormatException ignored) {
                // not numeric-with-s
            }
        }
        return parseRetryAfterValue(candidate);
    }

    private static Duration durationUntil(Instant when) {
        Instant now = Instant.now();
        if (when.isBefore(now)) {
            // Past — treat as "retry now" to avoid negative delays in the listener.
            return Duration.ZERO;
        }
        return Duration.between(now, when);
    }
}
