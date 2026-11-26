// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.interceptor;

import org.slf4j.MDC;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * {@link RestTemplate} interceptor that copies the current MDC trace IDs onto every outbound HTTP
 * request as standard headers, so any downstream service we call (Slack/Teams webhooks,
 * PagerDuty, ServiceNow, the notifier, etc.) sees the same {@code requestId} and
 * {@code correlationId} as our own logs.
 *
 * <p>Headers emitted (only when the MDC slot is populated — we never overwrite an existing header
 * the caller already set):
 * <ul>
 *   <li>{@code X-Request-ID}     — from MDC {@code requestId}</li>
 *   <li>{@code X-Correlation-ID} — from MDC {@code correlationId}</li>
 *   <li>{@code X-Message-ID}     — from MDC {@code messageId} (if present; helps when the
 *       outbound call is triggered by a queued message rather than an HTTP request)</li>
 * </ul>
 *
 * <p>The receiving side of our own services (the server's {@code RequestContextInterceptor})
 * already picks up these standard header names, so cross-service end-to-end tracing is automatic
 * with no further wiring on either end.
 */
@Component
public class TraceHeaderForwardingInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        addIfMissing(request, "X-Request-ID", MDC.get("requestId"));
        addIfMissing(request, "X-Correlation-ID", MDC.get("correlationId"));
        addIfMissing(request, "X-Message-ID", MDC.get("messageId"));
        return execution.execute(request, body);
    }

    private static void addIfMissing(HttpRequest request, String header, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        if (request.getHeaders().getFirst(header) != null) {
            return;
        }
        request.getHeaders().add(header, value);
    }
}
