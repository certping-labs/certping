// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.audit.AuditReason;
import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.constants.JwtClaims;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.SignInAccount;
import com.certmanagement.security.SignInEligibility;
import com.certmanagement.security.SignInRefusedException;
import com.certmanagement.security.oidc.PlatformOidcRegistration;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.service.audit.AuthAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.function.Function;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.SignInFailures;
import org.slf4j.Logger;

/**
 * Main service for SSO authentication orchestration: the OpenID Connect sign-in, once Spring Security
 * has verified the provider's token.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class SsoAuthenticationService {

    private final SsoAttributeExtractor attributeExtractor;
    private final UserProvisioningService userProvisioningService;
    private final JwtTokenProvider jwtTokenProvider;
    private final PlatformOidcRegistration platformOidcRegistration;
    private final RefreshTokenService refreshTokenService;
    private final AuthAuditRecorder authAuditRecorder;

    private static final AuditReason SSO_MISCONFIGURED = SignInFailures.SSO_MISCONFIGURED;
    private static final AuditReason SSO_REJECTED = SignInFailures.SSO_REJECTED;

    /**
     * Process OIDC authentication and return JWT tokens.
     */
    public AuthTokenResponse processOidcAuthentication(
            OAuth2AuthenticationToken authToken,
            String registrationId) {
        
        contextLogger().info("Processing OIDC authentication for registration: {}", registrationId);

        // Extract user info based on user type, with the organization's configured claim names and the
        // claim nominated as the stable subject identifier.
        return signIn(registrationId, ssoConfig -> {
            OAuth2User oauth2User = authToken.getPrincipal();
            return oauth2User instanceof OidcUser oidcUser
                    ? attributeExtractor.extractFromOidc(oidcUser, registrationId, ssoConfig)
                    : attributeExtractor.extractFromOAuth2(oauth2User, registrationId, ssoConfig);
        });
    }

    /**
     * The sign-in, once the protocol layer has verified the token.
     *
     * <p>The registration that validated it is the sole authority on tenant identity: it names exactly one
     * organization, and the token was verified against that registration's IdP. The IdP-asserted email is an attribute used to match a user *within* the tenant — it must
     * never be used to choose the tenant, since an IdP admin controls that value freely.
     *
     * <p>A refusal is on the audit trail ({@code auth.sign_in_failed}): in the member's trail once a member
     * was matched; else as an internal row naming only the organization whose configuration it came
     * through, and as an anonymous row in that organization's trail, throttled per reason. A success
     * is {@code auth.signed_in}.
     */
    private AuthTokenResponse signIn(String registrationId, Function<SsoConfig, SsoUserInfo> extract) {
        AuthAuditRecorder.Method method = AuthAuditRecorder.Method.OIDC;
        Long organizationId = null;
        String knownRegistrationId = null;
        try {
            SsoConfig ssoConfig = findSsoConfig(registrationId);
            // Known from here: a refusal that matches no member is written into this organization's trail.
            knownRegistrationId = ssoConfig.getRegistrationId();
            Organization organization = ssoConfig.getOrganization();
            organizationId = organization.getId();

            SsoUserInfo userInfo = extract.apply(ssoConfig);

            // Apply custom attribute mapping if configured
            if (ssoConfig.getAttributeMapping() != null) {
                userInfo = attributeExtractor.applyAttributeMapping(userInfo, ssoConfig.getAttributeMapping());
            }

            requireEmail(userInfo);

            // Find or provision user (JIT)
            User user = userProvisioningService.findOrProvisionUser(userInfo, organization, ssoConfig);
            SignInEligibility.require(user, organization);

            authAuditRecorder.signedIn(SignInAccount.of(user), method, registrationId);

            // Generate JWT tokens
            return generateAuthResponse(user, organization, userInfo);
        } catch (RuntimeException failure) {
            authAuditRecorder.ssoSignInFailed(failure, organizationId, method, knownRegistrationId);
            throw failure;
        }
    }

    /**
     * Generate authentication response with JWT tokens.
     */
    private AuthTokenResponse generateAuthResponse(User user, Organization organization, SsoUserInfo userInfo) {
        String accessToken = jwtTokenProvider.generateAccessToken(user, organization, userInfo.getAuthMethod());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user, organization);
        // Record the refresh token's JTI in auth_refresh_tokens so logout and password reset can
        // revoke it. Session origin: SSO (a password sign-in is LOCAL).
        refreshTokenService.recordIssued(refreshToken, user, JwtClaims.AUTH_METHOD_SSO);

        return AuthTokenResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .expiresIn(jwtTokenProvider.getExpirationTime())
            .userId(user.getId())
            .email(user.getEmail())
            .displayName(userInfo.getFullName())
                .organizationId(organization.getId())
                .organizationName(organization.getName())
            .roles(user.getRoleNames())
            .permissions(user.getEffectivePermissionNames())
            .build();
    }

    /** The configuration of the registration this token arrived on; only the platform provider has one. */
    private SsoConfig findSsoConfig(String registrationId) {
        if (!platformOidcRegistration.owns(registrationId)) {
            throw new SignInRefusedException(SSO_MISCONFIGURED, null, "SSO not configured");
        }
        return platformOidcRegistration.ssoConfig().orElseThrow(() -> new SignInRefusedException(
                SSO_MISCONFIGURED, null, "Single sign-on is not linked to an existing organization"));
    }

    /**
     * The IdP has to give us something to identify the person by. Tenancy no longer depends on the
     * email — the registration decides that — but {@code users.email} is NOT NULL and drives user
     * matching, audit records and notifications, so a blank one is rejected here with a clear error
     * rather than surfacing as a constraint violation part-way through provisioning.
     */
    private void requireEmail(SsoUserInfo userInfo) {
        if (userInfo.getEmail() == null || userInfo.getEmail().isBlank()) {
            throw new SignInRefusedException(SSO_REJECTED, null, "Identity provider did not supply an email address");
        }
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(SsoAuthenticationService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
