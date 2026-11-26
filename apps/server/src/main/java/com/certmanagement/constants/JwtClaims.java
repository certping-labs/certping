// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.constants;

/**
 * Constants for JWT claim names and well-known claim values.
 * Centralises every string keyed into or read from the JWT payload
 * so there is a single source of truth across JwtTokenProvider,
 * JwtAuthenticationFilter, and AuthController.
 */
public final class JwtClaims {

    private JwtClaims() {}

    // ── Claim names ────────────────────────────────────────────────────────────

    public static final String USER_ID      = "userId";
    public static final String ORGANIZATION_ID    = "organizationId";
    public static final String ORGANIZATION_NAME  = "organizationName";
    /** The organization type, always {@code B2B}; kept in the token for clients that read it. */
    public static final String ORG_TYPE     = "orgType";
    public static final String ROLES        = "roles";
    public static final String PERMISSIONS  = "permissions";
    public static final String AUTH_METHOD  = "authMethod";
    /** Distinguishes a refresh token from an access token. */
    public static final String TOKEN_TYPE   = "type";

    // ── Token-type values (value of the "type" claim) ─────────────────────────

    /** Value placed in the {@code type} claim of an access token; only these authenticate a request. */
    public static final String TOKEN_TYPE_ACCESS  = "access";
    /** Value placed in the {@code type} claim of a refresh token. */
    public static final String TOKEN_TYPE_REFRESH = "refresh";

    // ── Auth-method values (value of the "authMethod" claim) ──────────────────

    /** Local username/password authentication. */
    public static final String AUTH_METHOD_LOCAL = "LOCAL";
    /** SSO (OIDC) authentication. */
    public static final String AUTH_METHOD_SSO   = "SSO";
    /**
     * Social login (Google / GitHub / Microsoft / LinkedIn).
     *
     * <p><b>Used only on {@code auth_refresh_tokens.auth_method}</b> — not on the JWT's
     * {@code authMethod} claim nor on {@code users.auth_method}. Social-login users
     * have {@code users.auth_method=LOCAL} (the provider just vouches; they can set
     * a password via forgot-password); the SOCIAL tag is session-origin only.</p>
     */
    public static final String AUTH_METHOD_SOCIAL = "SOCIAL";

    // ── HTTP / token format ────────────────────────────────────────────────────

    public static final String BEARER_TYPE        = "Bearer";
    public static final String BEARER_PREFIX      = "Bearer ";
    public static final String AUTHORIZATION      = "Authorization";
    /** Spring Security authority prefix prepended to role names. */
    public static final String ROLE_PREFIX        = "ROLE_";
}
