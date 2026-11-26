// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/** Unit tests for {@link TraceHeaderForwardingInterceptor}. */
@ExtendWith(MockitoExtension.class)
class TraceHeaderForwardingInterceptorTest {

    @Mock private HttpRequest request;
    @Mock private ClientHttpRequestExecution execution;
    @Mock private ClientHttpResponse response;

    private final TraceHeaderForwardingInterceptor interceptor = new TraceHeaderForwardingInterceptor();

    @BeforeEach
    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void addsTraceHeadersFromMdcWhenPresent() throws Exception {
        MDC.put("requestId", "req-1");
        MDC.put("correlationId", "corr-2");
        MDC.put("messageId", "msg-3");
        HttpHeaders headers = new HttpHeaders();
        when(request.getHeaders()).thenReturn(headers);
        byte[] body = new byte[0];
        when(execution.execute(eq(request), eq(body))).thenReturn(response);

        ClientHttpResponse result = interceptor.intercept(request, body, execution);

        assertThat(result).isSameAs(response);
        assertThat(headers.getFirst("X-Request-ID")).isEqualTo("req-1");
        assertThat(headers.getFirst("X-Correlation-ID")).isEqualTo("corr-2");
        assertThat(headers.getFirst("X-Message-ID")).isEqualTo("msg-3");
    }

    @Test
    void skipsHeadersWhenMdcEmpty() throws Exception {
        // MDC is empty -> addIfMissing short-circuits and never touches request headers.
        when(execution.execute(any(), any())).thenReturn(response);

        ClientHttpResponse result = interceptor.intercept(request, new byte[0], execution);

        assertThat(result).isSameAs(response);
    }

    @Test
    void doesNotOverwriteExistingHeader() throws Exception {
        MDC.put("requestId", "mdc-req");
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Request-ID", "caller-set");
        when(request.getHeaders()).thenReturn(headers);
        when(execution.execute(any(), any())).thenReturn(response);

        interceptor.intercept(request, new byte[0], execution);

        assertThat(headers.getFirst("X-Request-ID")).isEqualTo("caller-set");
    }
}
