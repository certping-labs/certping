// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.interceptor.RequestContextInterceptor;
import jakarta.servlet.http.HttpServletRequest;

/**
 * The client address and ids of a single sign-on callback ({@code /login/oauth2/**}) for the audit rows and
 * log lines written while it is open. Those callbacks are handled by the security filter chain, outside the
 * {@code /api/**} {@link RequestContextInterceptor} that resolves them for every other request, so the
 * handler resolves them here and closes this when done, putting back what the thread held before. The ids
 * follow {@link SignInRequestIds}: a minted request id, which the failure redirect quotes as {@code ref}, and
 * any incoming request id kept as the correlation id.
 *
 * <pre>{@code
 * try (SignInCallbackClient client = SignInCallbackClient.open(clientAddressResolver, request)) {
 *     ...
 * }
 * }</pre>
 */
public final class SignInCallbackClient implements AutoCloseable {

    private final String previousClientIp;
    private final SignInRequestIds ids;

    private SignInCallbackClient(String previousClientIp, SignInRequestIds ids) {
        this.previousClientIp = previousClientIp;
        this.ids = ids;
    }

    public static SignInCallbackClient open(ClientAddressResolver resolver, HttpServletRequest request) {
        String previousClientIp = RequestContextInterceptor.getCurrentClientIp();
        RequestContextInterceptor.setCurrentClientIp(resolver.resolve(request));
        return new SignInCallbackClient(previousClientIp, SignInRequestIds.open(request));
    }

    /** The minted request id the callback's audit rows and log lines carry. */
    public String requestId() {
        return ids.requestId();
    }

    @Override
    public void close() {
        ids.close();
        RequestContextInterceptor.setCurrentClientIp(previousClientIp);
    }
}
