// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import java.time.Instant;

/** A verified refresh token. Only {@link JwtTokenProvider#parseRefreshToken} creates one. */
public record RefreshToken(
        String jti,
        String email,
        Integer userId,
        Long organizationId,
        Instant expiresAt) {
}
