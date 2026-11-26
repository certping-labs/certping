// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.service.audit.AuthAuditRecorder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * Handler for OIDC/OAuth2 authentication failures that happen before success handler invocation.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class OidcAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final AuthAuditRecorder authAuditRecorder;
    private final ClientAddressResolver clientAddressResolver;

    @Value("${app.frontend.redirect-url}")
    private String frontendRedirectUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String registrationId = extractRegistrationId(request.getRequestURI(), "unknown");
        AuditReason reason = SignInFailures.reasonOf(exception);
        String redirectUrl;
        // Opened first, so the log line, the audit rows and the redirect's ref share one request id.
        try (SignInCallbackClient client = SignInCallbackClient.open(clientAddressResolver, request)) {
            // A reason code, the framework's error code and the exception's type; never the exception's text,
            // which can quote the IdP's response, issuer URLs or key material names.
            log.warn("AUTH_EVENT authorization-auth failure authType=oidc registrationId={} method={} path={} reason={} providerError={} cause={}",
                registrationId,
                request.getMethod(),
                request.getRequestURI(),
                reason.code(),
                SignInFailures.providerErrorCode(errorCode(exception)),
                SignInFailures.causeOf(exception));
            // No account or organization is known yet: an internal anonymous row that names no one. The
            // registration id in the path is the caller's, so it is not recorded.
            authAuditRecorder.ssoSignInFailed(null, null, AuthAuditRecorder.Method.OIDC, null, reason);

            SsoSessionEvictionSupport.evictSessionAndCookies(request, response, log, "OIDC failure");
            redirectUrl = SignInFailureRedirect.url(frontendRedirectUrl, SignInFailures.GENERIC_MESSAGE, reason,
                    client.requestId());
        }
        response.sendRedirect(redirectUrl);
    }

    private static String errorCode(AuthenticationException exception) {
        return exception instanceof OAuth2AuthenticationException oauth && oauth.getError() != null
                ? oauth.getError().getErrorCode() : null;
    }

    private String extractRegistrationId(String requestUri, String fallback) {
        if (!StringUtils.hasText(requestUri)) {
            return fallback;
        }
        int lastSlash = requestUri.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == requestUri.length() - 1) {
            return fallback;
        }
        return requestUri.substring(lastSlash + 1);
    }
}
