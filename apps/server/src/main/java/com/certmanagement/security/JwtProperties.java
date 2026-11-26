// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Token settings, bound from {@code jwt.*}. The key settings are validated by {@link JwtSigningKeys}
 * at startup, so a bad deploy fails to boot instead of issuing tokens nobody can verify.
 *
 * @param issuer            {@code iss} written into and required on every token
 * @param audience          {@code aud} written into and required on every token
 * @param signingKeyId      {@code kid} of the key that signs new tokens; must be published
 * @param signingPrivateKey PKCS#8 PEM of that key
 * @param publishedKeys     JWKS JSON of every public key verifiers accept, served at
 *                          {@code /.well-known/jwks.json}
 * @param expiration        access-token lifetime in milliseconds
 * @param refreshExpiration refresh-token lifetime in milliseconds
 */
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        String issuer,
        String audience,
        String signingKeyId,
        String signingPrivateKey,
        String publishedKeys,
        long expiration,
        long refreshExpiration) {
}
