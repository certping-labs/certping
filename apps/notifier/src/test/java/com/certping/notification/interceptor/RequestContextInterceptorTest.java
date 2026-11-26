// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.interceptor;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class RequestContextInterceptorTest {

    private RequestContextInterceptor interceptor;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        interceptor = new RequestContextInterceptor();
        response = new MockHttpServletResponse();
        RequestContextInterceptor.clearContext();
    }

    @AfterEach
    void tearDown() {
        RequestContextInterceptor.clearContext();
    }

    // ── preHandle: header path ─────────────────────────────────────────────

    @Test
    void preHandle_setsAllThreeIdsFromHeaders() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("X-Request-ID", "req-abc");
        req.addHeader("X-Correlation-ID", "corr-xyz");
        req.addHeader("X-Idempotency-Key", "idem-123");

        boolean out = interceptor.preHandle(req, response, new Object());

        assertThat(out).isTrue();
        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("req-abc");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("corr-xyz");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("idem-123");
    }

    // ── preHandle: fall through to query param ─────────────────────────────

    @Test
    void preHandle_missingHeader_fallsBackToQueryParam() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setParameter("requestId", "req-from-query");
        req.setParameter("correlationId", "corr-from-query");

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("req-from-query");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("corr-from-query");
    }

    // ── preHandle: fall through to JSON body ───────────────────────────────

    @Test
    void preHandle_missingHeaderAndParam_extractsFromCachedBody() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        String body = "{\"requestId\":\"req-in-body\",\"correlationId\":\"corr-in-body\"}";
        req.setAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR,
                body.getBytes(StandardCharsets.UTF_8));

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("req-in-body");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("corr-in-body");
    }

    // ── preHandle: nothing anywhere → "unknown" default ────────────────────

    @Test
    void preHandle_nothingSet_defaultsToUnknown() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("none");
    }

    @Test
    void preHandle_emptyIdempotencyHeader_notSetAsCurrentKey() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("X-Idempotency-Key", ""); // empty → guard skips setting

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("none");
    }

    // ── extractFieldFromBody edge cases ────────────────────────────────────

    @Test
    void preHandle_emptyCachedBody_leavesUnknownDefault() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR, new byte[0]);

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
    }

    @Test
    void preHandle_cachedBodyIsMalformedJson_leavesUnknownDefault() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR,
                "this-is-not-json".getBytes(StandardCharsets.UTF_8));

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
    }

    @Test
    void preHandle_bodyHasFieldButItsNullNode_leavesUnknown() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR,
                "{\"requestId\":null}".getBytes(StandardCharsets.UTF_8));

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
    }

    @Test
    void preHandle_bodyHasFieldButItsEmptyString_leavesUnknown() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR,
                "{\"requestId\":\"\"}".getBytes(StandardCharsets.UTF_8));

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
    }

    @Test
    void preHandle_bodyFieldIsNumericNotString_leavesUnknown() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR,
                "{\"requestId\":12345}".getBytes(StandardCharsets.UTF_8));

        interceptor.preHandle(req, response, new Object());

        // Only textual node values are accepted — numeric ignored.
        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
    }

    // ── afterCompletion clears the ThreadLocals ────────────────────────────

    @Test
    void afterCompletion_removesAllContextThreadLocals() throws Exception {
        RequestContextInterceptor.setCurrentRequestId("r");
        RequestContextInterceptor.setCurrentCorrelationId("c");
        RequestContextInterceptor.setCurrentIdempotencyKey("i");

        interceptor.afterCompletion(new MockHttpServletRequest(), response, new Object(), null);

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("none");
    }

    // ── static setters/getters ─────────────────────────────────────────────

    @Test
    void staticSetters_roundTrip() {
        RequestContextInterceptor.setCurrentRequestId("r-1");
        RequestContextInterceptor.setCurrentCorrelationId("c-1");
        RequestContextInterceptor.setCurrentIdempotencyKey("i-1");

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("r-1");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("c-1");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("i-1");
    }

    @Test
    void getFormattedContext_withoutIdempotencyKey_omitsIt() {
        RequestContextInterceptor.setCurrentRequestId("r-9");
        RequestContextInterceptor.setCurrentCorrelationId("c-9");
        // Idempotency deliberately left unset (defaults to "none").

        String formatted = RequestContextInterceptor.getFormattedContext();

        assertThat(formatted)
                .contains("requestId=r-9")
                .contains("correlationId=c-9")
                .doesNotContain("idempotencyKey=");
    }

    @Test
    void getFormattedContext_withIdempotencyKey_includesIt() {
        RequestContextInterceptor.setCurrentRequestId("r-9");
        RequestContextInterceptor.setCurrentCorrelationId("c-9");
        RequestContextInterceptor.setCurrentIdempotencyKey("i-9");

        String formatted = RequestContextInterceptor.getFormattedContext();

        assertThat(formatted).contains("idempotencyKey=i-9");
    }

    @Test
    void extractValue_paramWithEmptyString_treatedAsMissing() throws Exception {
        // extractValue's second branch: header missing but query param present-but-empty.
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setParameter("requestId", "");

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
    }

    @Test
    void extractValue_headerWithEmptyString_fallsThroughToParam() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("X-Request-ID", ""); // empty header
        req.setParameter("requestId", "from-param");

        interceptor.preHandle(req, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("from-param");
    }
}
