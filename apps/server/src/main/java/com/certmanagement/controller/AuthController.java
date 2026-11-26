// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.dto.auth.LocalLoginResponse;
import com.certmanagement.dto.auth.UnifiedLoginRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.constants.JwtClaims;
import com.certmanagement.constants.Paths;
import com.certmanagement.security.AccessToken;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.Permissions;
import com.certmanagement.security.RefreshToken;
import com.certmanagement.security.SignInAccount;
import com.certmanagement.service.AccessTokenBlacklistService;
import com.certmanagement.service.RefreshTokenService;
import com.certmanagement.service.SessionRevocationService;
import com.certmanagement.service.UnifiedAuthService;
import com.certmanagement.service.audit.AuthAuditRecorder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "SSO authentication and token management")
public class AuthController {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenBlacklistService accessTokenBlacklistService;
    private final UnifiedAuthService unifiedAuthService;
    private final AuthAuditRecorder authAuditRecorder;

    /**
     * Unified login for local-password accounts (admins and members).
     *
     * The older {@code POST /api/v1/admin/login} on AdminController still works; this is the
     * friendlier email-or-username variant.
     */
    @PostMapping(Paths.AUTH_LOGIN)
    @Operation(summary = "Unified login (email or username)",
            description = "Login endpoint for local-password accounts. "
                    + "Identifier is treated as email if it contains '@', otherwise as username.")
    public ResponseEntity<LocalLoginResponse> login(@Valid @RequestBody UnifiedLoginRequest request) {
        return ResponseEntity.ok(unifiedAuthService.login(request));
    }

    @PostMapping(Paths.AUTH_REFRESH)
    @Operation(summary = "Refresh token", description = "Refresh access token using refresh token")
    public ResponseEntity<AuthTokenResponse> refreshToken(@RequestBody Map<String, String> request) {
        RefreshToken refreshToken = jwtTokenProvider.parseRefreshToken(request.get("refreshToken"))
                .orElseThrow(() -> new BadRequestException("Invalid refresh token"));

        // Reject revoked refresh tokens up-front (post-logout, post-rotation).
        if (refreshTokenService.isBlacklisted(refreshToken)) {
            throw new UnauthorizedException("Refresh token has been revoked");
        }

        String email = refreshToken.email();
        Integer tokenUserId = refreshToken.userId();
        Long tokenOrganizationId = refreshToken.organizationId();
        
        User user = null;
        if (tokenUserId != null) {
            user = userRepository.findById(tokenUserId).orElse(null);
            if (user != null && (user.getEmail() == null || !user.getEmail().equalsIgnoreCase(email))) {
                throw new UnauthorizedException("Refresh token does not match user identity");
            }
        }

        // Backward compatibility: only allow fallback when refresh token carries organization scope.
        if (user == null) {
            if (tokenOrganizationId != null) {
                user = userRepository.findByEmailAndOrganizationId(email, tokenOrganizationId).orElse(null);
            }
        }

        if (user == null || !Boolean.TRUE.equals(user.getActive())) {
            throw new UnauthorizedException("User is not authorized");
        }

        Organization organization = user.getOrganization();
        if (organization != null
                && (!Boolean.TRUE.equals(organization.getActive()) || Boolean.TRUE.equals(organization.getIsDeleted()))) {
            throw new UnauthorizedException("Organization is suspended or inactive");
        }
        Long userOrganizationId = organization != null ? organization.getId() : null;
        if (tokenOrganizationId != null && !tokenOrganizationId.equals(userOrganizationId)) {
            throw new UnauthorizedException("Refresh token organization does not match user organization");
        }

        // authMethod for the refreshed JWT reflects the user's account-level auth method
        // (LOCAL or SSO — matches users.auth_method). Not the session-origin tag.
        String authMethod = user.getAuthMethod() != null
            ? user.getAuthMethod().name()
            : JwtClaims.AUTH_METHOD_LOCAL;

        String newAccessToken = jwtTokenProvider.generateAccessToken(user, organization, authMethod);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user, organization);

        // Rotation: keep the session-origin recorded on the OLD refresh-token row, so the session
        // reports how it was started through every rotation. Falls back to the user's
        // account-level authMethod if the old row is missing (an older token).
        String sessionOrigin = refreshTokenService.getRecordedAuthMethod(refreshToken);
        if (sessionOrigin == null) {
            sessionOrigin = authMethod;
        }
        refreshTokenService.recordIssued(newRefreshToken, user, sessionOrigin);
        refreshTokenService.blacklist(refreshToken);

        return ResponseEntity.ok(AuthTokenResponse.builder()
            .accessToken(newAccessToken)
            .refreshToken(newRefreshToken)
            .tokenType(JwtClaims.BEARER_TYPE)
            .expiresIn(jwtTokenProvider.getExpirationTime())
            .userId(user.getId())
            .email(user.getEmail())
            .organizationId(organization != null ? organization.getId() : null)
            .organizationName(organization != null ? organization.getName() : null)
            .roles(user.getRoleNames())
            .permissions(user.getEffectivePermissionNames())
            .build());
    }

    @PostMapping(Paths.AUTH_VALIDATE)
    @Operation(summary = "Validate token", description = "Validate a JWT token and return claims")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestBody Map<String, String> request) {
        Optional<AccessToken> token = jwtTokenProvider.parseAccessToken(request.get("token"))
                .filter(t -> !accessTokenBlacklistService.isRevoked(t.jti()));

        Map<String, Object> response = new HashMap<>();
        response.put("valid", token.isPresent());
        token.ifPresent(t -> putClaims(response, t));
        return ResponseEntity.ok(response);
    }

    @GetMapping(Paths.AUTH_ME)
    @Operation(summary = "Get current user", description = "Get current user info from JWT token")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            @RequestHeader("Authorization") String authHeader) {
        
        if (authHeader == null || !authHeader.startsWith(JwtClaims.BEARER_PREFIX)) {
            throw new BadRequestException("Authorization header must use Bearer token");
        }

        AccessToken token = jwtTokenProvider.parseAccessToken(authHeader.substring(JwtClaims.BEARER_PREFIX.length()))
                .orElseThrow(() -> new UnauthorizedException("Invalid or expired access token"));
        if (accessTokenBlacklistService.isRevoked(token.jti())) {
            throw new UnauthorizedException("Access token has been revoked");
        }
        // This path bypasses JwtAuthenticationFilter, so the user's tokens_valid_after is checked here too.
        if (token.userId() != null && userRepository.findAccessStateById(token.userId())
                .filter(state -> SessionRevocationService.refuses(token, state.getTokensValidAfter(),
                        accessTokenBlacklistService))
                .isPresent()) {
            throw new UnauthorizedException("Access token has been revoked");
        }

        Map<String, Object> userInfo = new HashMap<>();
        putClaims(userInfo, token);
        return ResponseEntity.ok(userInfo);
    }

    @PostMapping(Paths.AUTH_LOGOUT)
    @Operation(summary = "Logout",
            description = "Revoke the current access token and the supplied refresh token. "
                    + "Body is optional: pass {refreshToken} to also revoke the refresh token.")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            @RequestBody(required = false) Map<String, String> body) {

        Optional<AccessToken> accessToken = jwtTokenProvider.parseAccessToken(extractBearerToken(request));
        accessToken.ifPresent(accessTokenBlacklistService::revoke);

        Optional<RefreshToken> refreshToken = jwtTokenProvider.parseRefreshToken(body == null ? null : body.get("refreshToken"));
        if (refreshToken.isPresent()) {
            refreshTokenService.blacklist(refreshToken.get());
        } else {
            Integer userId = GatewayRequestContext.getUserId();
            log.debug("Logout without refresh-token body — refresh revocation skipped (userId={})", userId);
        }
        recordSignOut(accessToken, refreshToken);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Logged out successfully");
        return ResponseEntity.ok(response);
    }

    /**
     * {@code auth.signed_out} for the account a verified token names: the access token when it still
     * verifies, else the refresh token (an access token can expire before its session ends). A logout that
     * presents neither revoked nothing and names no one, so it writes no row.
     */
    private void recordSignOut(Optional<AccessToken> accessToken, Optional<RefreshToken> refreshToken) {
        if (accessToken.isPresent() && accessToken.get().userId() != null) {
            AccessToken token = accessToken.get();
            boolean superAdmin = token.roles() != null && token.roles().contains(Permissions.ROLE_SUPER_ADMIN);
            authAuditRecorder.signedOut(new SignInAccount(token.userId(), token.organizationId(), superAdmin),
                    token.authMethod());
        } else if (refreshToken.isPresent() && refreshToken.get().userId() != null) {
            RefreshToken token = refreshToken.get();
            // A refresh token carries no roles: staff are recognised by having no organization.
            authAuditRecorder.signedOut(new SignInAccount(token.userId(), token.organizationId(), false), null);
        }
    }

    private static void putClaims(Map<String, Object> target, AccessToken token) {
        target.put("email", token.email());
        target.put("userId", token.userId());
        target.put("organizationId", token.organizationId());
        target.put("roles", token.roles());
        target.put("permissions", token.permissions());
    }

    private String extractBearerToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(JwtClaims.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(JwtClaims.BEARER_PREFIX)) {
            return bearerToken.substring(JwtClaims.BEARER_PREFIX.length());
        }
        return null;
    }
}
