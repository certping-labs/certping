// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import java.time.Instant;
import java.util.List;

/**
 * A verified access token. Only {@link JwtTokenProvider#parseAccessToken} creates one.
 *
 * @param issuedAt the {@code iat} claim (whole seconds); null when the token has none
 */
public record AccessToken(
        String jti,
        String email,
        Integer userId,
        Long organizationId,
        List<String> roles,
        List<String> permissions,
        String authMethod,
        Instant expiresAt,
        Instant issuedAt) {

    public AccessToken(String jti, String email, Integer userId, Long organizationId, List<String> roles,
                       List<String> permissions, String authMethod, Instant expiresAt) {
        this(jti, email, userId, organizationId, roles, permissions, authMethod, expiresAt, null);
    }
}
