// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.certmanagement.constants.JwtClaims;
import com.certmanagement.constants.Paths;
import com.certmanagement.repository.ActivationStateProjection;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserAccessStateProjection;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.service.AccessTokenBlacklistService;
import com.certmanagement.service.SessionRevocationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * JWT authentication filter that validates tokens and sets the Spring Security context.
 * Handles both LOCAL and SSO-issued tokens uniformly.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /** Request attribute holding the verified {@link AccessToken} of an authenticated request. */
    public static final String ACCESS_TOKEN_ATTRIBUTE = JwtAuthenticationFilter.class.getName() + ".accessToken";

    /** The 403 for a user who must change the password first; {@code code} is what clients branch on. */
    static final String PASSWORD_CHANGE_REQUIRED_BODY =
            "{\"error\":\"Change your password to continue\",\"code\":\"PASSWORD_CHANGE_REQUIRED\"}";

    private static final java.util.Set<String> PASSWORD_CHANGE_ALLOWED_PATHS = java.util.Set.of(
            Paths.AUTH_CHANGE_PASSWORD,
            Paths.ADMIN_CHANGE_PW,
            Paths.AUTH_LOGOUT,
            Paths.AUTH_REFRESH,
            Paths.AUTH_ME,
            Paths.DEPLOYMENT_INFO);

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final AccessTokenBlacklistService accessTokenBlacklistService;


    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        String method = request.getMethod();
        String path = request.getRequestURI();
        String requestIdFromHeader = request.getHeader("X-Request-ID");
        String correlationIdFromHeader = request.getHeader("X-Correlation-ID");

        try {
            String jwt = extractJwtFromRequest(request);

            if (StringUtils.hasText(jwt)) {
                Optional<AccessToken> parsed = jwtTokenProvider.parseAccessToken(jwt);
                if (parsed.isEmpty()) {
                    log.warn("[reqId={}|corrId={}] AUTH_EVENT resource-auth failure authType=jwt method={} path={} reason=invalid_token",
                            StringUtils.hasText(requestIdFromHeader) ? requestIdFromHeader : "unknown",
                            StringUtils.hasText(correlationIdFromHeader) ? correlationIdFromHeader : "unknown",
                            method,
                            path);
                } else {
                    AccessToken token = parsed.get();
                    // Reject revoked access tokens before any further processing.
                    String jti = token.jti();
                    if (jti != null && accessTokenBlacklistService.isRevoked(jti)) {
                        log.warn("AUTH_EVENT resource-auth failure authType=jwt reason=access_token_revoked jti={}", jti);
                        rejectRequest(response, HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked");
                        return;
                    }

                    String email = token.email();
                    List<String> roles = token.roles();

                    Integer userId = token.userId();
                    Long organizationIdLong = token.organizationId();
                    String organizationId = organizationIdLong != null ? organizationIdLong.toString() : null;
                    String requestId = "req-" + UUID.randomUUID();

                    if (userId != null) {
                        UserAccessStateProjection tokenUser =
                                userRepository.findAccessStateById(userId).orElse(null);
                        if (tokenUser == null
                                || !Boolean.TRUE.equals(tokenUser.getActive())
                                || Boolean.TRUE.equals(tokenUser.getIsDeleted())) {
                            log.warn("[reqId={}] AUTH_EVENT active-check failure userId={} reason=user_inactive_or_deleted",
                                    requestId, userId);
                            rejectRequest(response, HttpServletResponse.SC_UNAUTHORIZED, "Account is disabled or deleted");
                            return;
                        }
                        // Issued before the user's password or access last changed: the client refreshes (new
                        // roles) or, after a password change, signs in again.
                        if (SessionRevocationService.refuses(token, tokenUser.getTokensValidAfter(),
                                accessTokenBlacklistService)) {
                            log.warn("[reqId={}] AUTH_EVENT resource-auth failure userId={} reason=token_issued_before_revocation",
                                    requestId, userId);
                            rejectRequest(response, HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked");
                            return;
                        }
                        if (Boolean.TRUE.equals(tokenUser.getMustChangePassword()) && !allowedBeforePasswordChange(path)) {
                            log.info("[reqId={}] AUTH_EVENT resource-auth refused userId={} reason=password_change_required",
                                    requestId, userId);
                            writeJson(response, HttpServletResponse.SC_FORBIDDEN, PASSWORD_CHANGE_REQUIRED_BODY);
                            return;
                        }
                        if (organizationIdLong != null) {
                            ActivationStateProjection tokenOrg = organizationRepository
                                    .findActivationStateById(organizationIdLong).orElse(null);
                            if (tokenOrg != null
                                    && (!Boolean.TRUE.equals(tokenOrg.getActive()) || Boolean.TRUE.equals(tokenOrg.getIsDeleted()))) {
                                log.warn("[reqId={}] AUTH_EVENT active-check failure userId={} orgId={} reason=org_inactive_or_deleted",
                                        requestId, userId, organizationIdLong);
                                rejectRequest(response, HttpServletResponse.SC_UNAUTHORIZED, "Organization is suspended or inactive");
                                return;
                            }
                        }
                    }

                    // Expose userId as request attribute (used by password-change endpoint)
                    if (userId != null) {
                        request.setAttribute(JwtClaims.USER_ID, userId);
                    }
                    // The password change keeps this token working while it ends every other session.
                    request.setAttribute(ACCESS_TOKEN_ATTRIBUTE, token);

                    GatewayRequestContext.set(userId, organizationId, requestId, email);
                    // Mirror into MDC so this filter's own AUTH_EVENT log line and every log line
                    // emitted on the request thread (before RequestContextInterceptor.preHandle runs)
                    // carries [req= corr= org=] in the prefix. The interceptor will overwrite with
                    // the same values when it runs, and clear in afterCompletion.
                    MDC.put("requestId", requestId);
                    if (StringUtils.hasText(correlationIdFromHeader)) {
                        MDC.put("correlationId", correlationIdFromHeader);
                    }
                    if (organizationId != null && !organizationId.isEmpty()) {
                        MDC.put("organizationId", organizationId);
                    }
                    log.debug("GatewayRequestContext configured — requestId: {}, organizationId: {}",
                            requestId, organizationId);

                    List<SimpleGrantedAuthority> authorities = new ArrayList<>();

                    // Map role names to Spring ROLE_ prefix authorities
                    if (roles != null) {
                        roles.stream()
                            .map(role -> new SimpleGrantedAuthority(JwtClaims.ROLE_PREFIX + role))
                            .forEach(authorities::add);
                    }

                    // Add permissions directly as authorities (used by hasPermission() evaluator)
                    List<String> permissions = token.permissions();
                    if (permissions != null) {
                        permissions.stream()
                            .map(SimpleGrantedAuthority::new)
                            .forEach(authorities::add);
                    }

                    UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(email, null, authorities);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info("[reqId={}|corrId={}] AUTH_EVENT resource-auth success authType=jwt organizationId={} method={} path={} rolesCount={} permissionsCount={}"
                                    + ", authHeaderPresent=true",
                            requestId,
                            StringUtils.hasText(correlationIdFromHeader) ? correlationIdFromHeader : "unknown",
                            organizationId,
                            method,
                            path,
                            roles != null ? roles.size() : 0,
                            permissions != null ? permissions.size() : 0);
                }
            }
        } catch (Exception ex) {
            // The fields carry a code and the exception's type; the stack trace follows for diagnosis.
            log.error("[reqId={}|corrId={}] AUTH_EVENT resource-auth error authType=jwt method={} path={} reason=INTERNAL_ERROR cause={}",
                    StringUtils.hasText(requestIdFromHeader) ? requestIdFromHeader : "unknown",
                    StringUtils.hasText(correlationIdFromHeader) ? correlationIdFromHeader : "unknown",
                    method,
                    path,
                    SignInFailures.causeOf(ex),
                    ex);
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            GatewayRequestContext.clear();
            // A request that never reaches the interceptor's afterCompletion must not leave its ids on this thread.
            MDC.remove("requestId");
            MDC.remove("correlationId");
            MDC.remove("organizationId");
        }
    }

    private void rejectRequest(HttpServletResponse response, int status, String message) throws IOException {
        writeJson(response, status, "{\"error\":\"" + message + "\"}");
    }

    private static void writeJson(HttpServletResponse response, int status, String json) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(json);
    }

    /**
     * What a user who still owes a password change may call: the change itself, sign-out and refresh, the
     * profile the web app loads ({@code /api/auth/me}) and the public deployment info. The {@code /api/auth}
     * ones mostly bypass this filter already; they are listed so the rule reads in one place.
     */
    static boolean allowedBeforePasswordChange(String path) {
        if (path == null) {
            return false;
        }
        String normalized = path.length() > 1 && path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        return PASSWORD_CHANGE_ALLOWED_PATHS.contains(normalized);
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(JwtClaims.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(JwtClaims.BEARER_PREFIX)) {
            return bearerToken.substring(JwtClaims.BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (org.springframework.http.HttpMethod.OPTIONS.matches(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();

        // /api/auth/change-password and the account's own two-factor endpoints (/api/auth/mfa, its enroll
        // and confirm) need the full filter (SecurityContext + blacklist). /api/auth/login/mfa is the
        // anonymous second sign-in step. /api/auth/me and /api/auth/validate check the blacklist inline.
        // Other /api/auth/* paths are anonymous or self-revoking (logout).
        if (path.equals(Paths.AUTH_CHANGE_PASSWORD) || path.equals(Paths.AUTH_MFA)
                || path.startsWith(Paths.AUTH_MFA + "/")) {
            return false;
        }

        return path.startsWith("/api/v1/agent-gateway/") ||
               path.startsWith("/login/") ||
               path.startsWith("/oauth2/") ||
               path.startsWith("/api/auth/") ||
               path.startsWith("/api/v1/internal/") ||
               path.equals(Paths.PUBLIC_STATUS) ||
               path.equals(Paths.JWKS) ||
               path.equals(Paths.ADMIN_LOGIN) ||
               path.equals(Paths.ADMIN_STATUS);
    }
}
