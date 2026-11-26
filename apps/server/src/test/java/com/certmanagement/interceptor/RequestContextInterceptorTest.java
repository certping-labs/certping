// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import com.certmanagement.security.ClientAddressResolver;
import com.certmanagement.security.ClientIpSource;
import com.certmanagement.security.GatewayRequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.MDC;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RequestContextInterceptorTest {

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;

    private RequestContextInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new RequestContextInterceptor(new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null));
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        RequestContextInterceptor.clearContext();
        MDC.clear();
    }

    @Test
    void preHandle_noContextNoHeaders_mintsIds() throws Exception {
        boolean result = interceptor.preHandle(request, response, new Object());

        assertThat(result).isTrue();
        assertThat(RequestContextInterceptor.getCurrentRequestId()).startsWith("req-http-");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).startsWith("corr-http-");
        verify(response).setHeader(eq("X-Request-ID"), org.mockito.ArgumentMatchers.startsWith("req-http-"));
    }

    @Test
    void preHandle_usesHeaders() throws Exception {
        when(request.getHeader("X-Request-ID")).thenReturn("hdr-req");
        when(request.getHeader("X-Correlation-ID")).thenReturn("hdr-corr");
        when(request.getHeader("X-Idempotency-Key")).thenReturn("idem-1");

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("hdr-req");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("hdr-corr");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("idem-1");
        assertThat(MDC.get("requestId")).isEqualTo("hdr-req");
        assertThat(MDC.get("correlationId")).isEqualTo("hdr-corr");
        assertThat(MDC.get("idempotencyKey")).isEqualTo("idem-1");
    }

    @Test
    void theIdsAreReadFromTheMdc() {
        MDC.put("requestId", "mdc-req");
        MDC.put("correlationId", "mdc-corr");
        MDC.put("idempotencyKey", "mdc-idem");

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("mdc-req");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("mdc-corr");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("mdc-idem");
    }

    @Test
    void preHandle_fallsBackToQueryParams() throws Exception {
        when(request.getHeader("X-Request-ID")).thenReturn(null);
        when(request.getParameter("requestId")).thenReturn("param-req");
        when(request.getHeader("X-Correlation-ID")).thenReturn("");
        when(request.getParameter("correlationId")).thenReturn("param-corr");

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("param-req");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("param-corr");
    }

    @Test
    void preHandle_extractsCorrelationIdFromCachedJsonBody() throws Exception {
        when(request.getHeader("X-Correlation-ID")).thenReturn(null);
        when(request.getParameter("correlationId")).thenReturn(null);
        byte[] body = "{\"correlationId\":\"body-corr\"}".getBytes(StandardCharsets.UTF_8);
        when(request.getAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR)).thenReturn(body);

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("body-corr");
    }

    @Test
    void preHandle_invalidJsonBody_mintsCorrelationId() throws Exception {
        when(request.getHeader("X-Correlation-ID")).thenReturn(null);
        when(request.getParameter("correlationId")).thenReturn(null);
        when(request.getAttribute(RequestBodyCachingFilter.CACHED_BODY_ATTR))
                .thenReturn("not-json".getBytes(StandardCharsets.UTF_8));

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).startsWith("corr-http-");
    }

    @Test
    void preHandle_withGatewayContext_usesGatewayRequestIdAndOrg() throws Exception {
        GatewayRequestContext.set(42, "org-7", "jwt-req", "u@x.io");

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("jwt-req");
        assertThat(MDC.get("organizationId")).isEqualTo("org-7");
        // correlationId mirrored back into gateway context
        assertThat(GatewayRequestContext.getCorrelationId()).startsWith("corr-http-");
    }

    @Test
    void afterCompletion_clearsTheMdcKeysItOwns() throws Exception {
        RequestContextInterceptor.setCurrentRequestId("r");
        RequestContextInterceptor.setCurrentCorrelationId("c");
        RequestContextInterceptor.setCurrentIdempotencyKey("k");
        MDC.put("other", "kept");

        interceptor.afterCompletion(request, response, new Object(), null);

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("none");
        assertThat(MDC.getCopyOfContextMap()).containsExactlyEntriesOf(Map.of("other", "kept"));
    }

    @Test
    void staticGetters_defaultsWhenUnset() {
        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("none");
    }

    @Test
    void getFormattedContext_withAndWithoutIdempotencyKey() {
        RequestContextInterceptor.setCurrentRequestId("r1");
        RequestContextInterceptor.setCurrentCorrelationId("c1");
        assertThat(RequestContextInterceptor.getFormattedContext())
                .isEqualTo("requestId=r1, correlationId=c1");

        RequestContextInterceptor.setCurrentIdempotencyKey("idem-9");
        assertThat(RequestContextInterceptor.getFormattedContext())
                .contains("idempotencyKey=idem-9");
    }

    @Test
    void settingNullRemovesTheId() {
        RequestContextInterceptor.setCurrentRequestId("r");
        RequestContextInterceptor.setCurrentCorrelationId("c");
        RequestContextInterceptor.setCurrentIdempotencyKey("k");

        RequestContextInterceptor.setCurrentRequestId(null);
        RequestContextInterceptor.setCurrentCorrelationId(null);
        RequestContextInterceptor.setCurrentIdempotencyKey(null);

        assertThat(RequestContextInterceptor.getCurrentRequestId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentCorrelationId()).isEqualTo("unknown");
        assertThat(RequestContextInterceptor.getCurrentIdempotencyKey()).isEqualTo("none");
        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
    }

    @Test
    void preHandle_takesTheClientAddressFromTheResolverNotTheClientWrittenForwardedEntry() throws Exception {
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        forwardedFor("203.0.113.5, 198.51.100.7");

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentClientIp()).isEqualTo("198.51.100.7");
        assertThat(MDC.getCopyOfContextMap()).doesNotContainValue("198.51.100.7");
    }

    @Test
    void preHandle_noLongerReadsRealIp() throws Exception {
        when(request.getHeader("X-Real-IP")).thenReturn("2001:db8::7");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentClientIp()).isEqualTo("127.0.0.1");
    }

    @Test
    void aForwardedEntryThatIsNotAnIpLiteralIsNotStored() throws Exception {
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        forwardedFor("hello");

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentClientIp()).isEqualTo("10.0.0.1");
    }

    @Test
    void noReadableAddressStoresNull() throws Exception {
        when(request.getRemoteAddr()).thenReturn("not-an-ip");

        interceptor.preHandle(request, response, new Object());

        assertThat(RequestContextInterceptor.getCurrentClientIp()).isNull();
    }

    private void forwardedFor(String value) {
        when(request.getHeaders("X-Forwarded-For")).thenAnswer(inv -> Collections.enumeration(List.of(value)));
        when(request.getHeader("X-Forwarded-For")).thenReturn(value);
    }

    @Test
    void theClientAddressIsClearedAfterTheRequest() throws Exception {
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        interceptor.preHandle(request, response, new Object());

        interceptor.afterCompletion(request, response, new Object(), null);

        assertThat(RequestContextInterceptor.getCurrentClientIp()).isNull();
    }
}
