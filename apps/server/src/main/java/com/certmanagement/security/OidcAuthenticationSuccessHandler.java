// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.service.SsoAuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Handler for successful OIDC/OAuth2 authentication.
 * Delegates to SsoAuthenticationService for user provisioning and JWT generation.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OidcAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final SsoAuthenticationService ssoAuthenticationService;
    private final ClientAddressResolver clientAddressResolver;
    private final SsoLoginCodes ssoLoginCodes;

    @Value("${app.frontend.redirect-url}")
    private String frontendRedirectUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        // The callback runs in the security filter chain, outside the /api interceptor: resolve the client and
        // the request id here so the audit rows the sign-in writes carry them.
        try (SignInCallbackClient client = SignInCallbackClient.open(clientAddressResolver, request)) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();

            log.info("AUTH_EVENT authorization-auth success authType=oidc registrationId={} method={} path={}",
                registrationId,
                request.getMethod(),
                request.getRequestURI());

            try {
                AuthTokenResponse authResponse = ssoAuthenticationService.processOidcAuthentication(
                    oauthToken, registrationId
                );

                redirectWithTokens(request, response, authResponse);

            } catch (Exception e) {
                // A reason code and the exception's type, never its text; the service wrote the audit row.
                log.warn("AUTH_EVENT authorization-auth failure authType=oidc registrationId={} method={} path={} reason={} cause={}",
                        registrationId,
                        request.getMethod(),
                        request.getRequestURI(),
                        SignInFailures.reasonOf(e).code(),
                        SignInFailures.causeOf(e));
                log.error("Failed to process OIDC authentication", e);
                redirectWithError(request, response, SignInFailures.clientMessage(e), SignInFailures.reasonOf(e),
                        client.requestId());
            }
        }
    }

    private void redirectWithTokens(HttpServletRequest request,
                                    HttpServletResponse response,
                                    AuthTokenResponse authResponse) throws IOException {
        // The tokens stay server side: the web app trades this one-time code for them (POST /api/auth/sso/exchange).
        String code = ssoLoginCodes.issue(authResponse);
        SsoSessionEvictionSupport.evictSessionAndCookies(request, response, log, "OIDC success");

        String redirectUrl = UriComponentsBuilder.fromUriString(frontendRedirectUrl)
            .queryParam("code", code)
            .build()
            .toUriString();

        response.sendRedirect(redirectUrl);
    }

    private void redirectWithError(HttpServletRequest request,
                                   HttpServletResponse response,
                                   String message,
                                   AuditReason reason,
                                   String requestId) throws IOException {
        SsoSessionEvictionSupport.evictSessionAndCookies(request, response, log, "OIDC error");

        response.sendRedirect(SignInFailureRedirect.url(frontendRedirectUrl, message, reason, requestId));
    }
}
