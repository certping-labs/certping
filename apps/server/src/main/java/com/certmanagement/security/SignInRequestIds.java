// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.interceptor.RequestContextInterceptor;
import jakarta.servlet.http.HttpServletRequest;

import java.util.UUID;

/**
 * The ids of a single sign-on callback, for the {@code AUTH_EVENT} lines, the audit rows
 * and the failure redirect's {@code ref} written while it is open.
 *
 * <p>The request id is always minted here ({@code req-http-<uuid>}). The {@code ref} the person quotes is
 * then always an id the server chose, never one a link or a client supplied. An incoming
 * {@code X-Request-ID} header or {@code requestId} parameter, when it is a plain token, is kept as the
 * correlation id instead, so it can still be traced. An explicit {@code X-Correlation-ID} the
 * {@code /api} interceptor already resolved wins over it.
 *
 * <p>Closing puts back what the thread held before.
 */
public final class SignInRequestIds implements AutoCloseable {

    static final String REQUEST_ID_HEADER = "X-Request-ID";
    static final String REQUEST_ID_PARAM = "requestId";
    private static final String MINTED_CORRELATION_PREFIX = "corr-http-";

    private final String previousRequestId;
    private final String previousCorrelationId;
    private final String requestId;

    private SignInRequestIds(String previousRequestId, String previousCorrelationId, String requestId) {
        this.previousRequestId = previousRequestId;
        this.previousCorrelationId = previousCorrelationId;
        this.requestId = requestId;
    }

    public static SignInRequestIds open(HttpServletRequest request) {
        String previousRequestId = known(RequestContextInterceptor.getCurrentRequestId());
        String previousCorrelationId = known(RequestContextInterceptor.getCurrentCorrelationId());

        String requestId = "req-http-" + UUID.randomUUID();
        RequestContextInterceptor.setCurrentRequestId(requestId);

        String incoming = plainToken(request.getHeader(REQUEST_ID_HEADER));
        if (incoming == null) {
            incoming = plainToken(request.getParameter(REQUEST_ID_PARAM));
        }
        boolean explicitCorrelation = previousCorrelationId != null
                && !previousCorrelationId.startsWith(MINTED_CORRELATION_PREFIX);
        if (incoming != null && !explicitCorrelation) {
            RequestContextInterceptor.setCurrentCorrelationId(incoming);
        }
        return new SignInRequestIds(previousRequestId, previousCorrelationId, requestId);
    }

    /** The minted request id: what the audit rows, the log lines and the redirect's {@code ref} carry. */
    public String requestId() {
        return requestId;
    }

    @Override
    public void close() {
        RequestContextInterceptor.setCurrentRequestId(previousRequestId);
        RequestContextInterceptor.setCurrentCorrelationId(previousCorrelationId);
    }

    private static String plainToken(String value) {
        return value == null ? null : SignInFailureRedirect.reference(value);
    }

    private static String known(String id) {
        return id == null || id.isBlank() || "unknown".equals(id) ? null : id;
    }
}
