// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Centralized logger for Spring Security authentication events emitted by
 * the framework authentication manager/providers.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationEventLogger {

    private final ClientAddressResolver clientAddressResolver;

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();
        log.info("AUTH_EVENT framework-auth success eventType={} authClass={} authoritiesCount={} details={}",
                event.getClass().getSimpleName(),
                authentication != null ? authentication.getClass().getSimpleName() : "unknown",
                authentication != null && authentication.getAuthorities() != null
                        ? authentication.getAuthorities().size() : 0,
                resolveDetails(authentication));
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        Authentication authentication = event.getAuthentication();
        // A reason code and the exception's type, never its text (which can quote the IdP's response).
        log.warn("AUTH_EVENT framework-auth failure eventType={} authClass={} details={} reason={} cause={}",
                event.getClass().getSimpleName(),
                authentication != null ? authentication.getClass().getSimpleName() : "unknown",
                resolveDetails(authentication),
                SignInFailures.reasonOf(event.getException()).code(),
                SignInFailures.causeOf(event.getException()));
    }

    private String resolvePrincipal(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return "anonymous";
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        }
        if (principal instanceof OAuth2AuthenticatedPrincipal oauth2Principal) {
            return oauth2Principal.getName();
        }
        return String.valueOf(principal);
    }

    String resolveDetails(Authentication authentication) {
        if (authentication == null || authentication.getDetails() == null) {
            return "none";
        }

        Object details = authentication.getDetails();
        if (details instanceof WebAuthenticationDetails webDetails) {
            return "remoteIp=" + clientIp(webDetails) + ",sessionId=" + webDetails.getSessionId();
        }
        return details.getClass().getSimpleName();
    }

    /** The resolver's answer for the request being authenticated, else the address Spring Security captured. */
    private String clientIp(WebAuthenticationDetails details) {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servlet) {
            return clientAddressResolver.resolve(servlet.getRequest());
        }
        return details.getRemoteAddress();
    }
}
